#include <iostream>
#include <cstdio>
#include <string>
#include <fstream>
#include <unordered_map>
#include "client_helper.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sstream>

using namespace std;

const string files_path = "client_files";
const string cert_path = "client_files/cert.pem";
const string key_path = "client_files/key.pem";
const string id_path = "client_files/recipient_id.txt";

string exec(const string& cmd) {
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        cerr << "popen() failed!" <<endl;
        exit(1);
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (result.back()=='\n') result.pop_back();
    return result;
}

void send_request(BIO *bio, string msg) {
    msg += "\r\n\r\n";
    string request = my::generate_header(msg.size());
    request += msg;
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void send_msg(BIO *bio, string recipient) {
    ifstream f1("tmp/key.bin.enc", ifstream::binary);
    string keyenc((std::istreambuf_iterator<char>(f1)), std::istreambuf_iterator<char>());
    f1.close();
    ifstream f2("tmp/id_mail.enc", ifstream::binary);
    string idmail((std::istreambuf_iterator<char>(f2)), std::istreambuf_iterator<char>());
    f2.close();
    ifstream f3("tmp/signature.sign", ifstream::binary);
    string sg((std::istreambuf_iterator<char>(f3)), std::istreambuf_iterator<char>());
    f3.close();

    send_request(bio, keyenc);
    send_request(bio, idmail);
    send_request(bio, sg);
}

/*
parameter:  username: recipient name
            idmap: the ID (number) of the mail for the recipient
output: 3 files:  key.bin.enc - the key used for symmetric encryption
                  id_mail.enc - [id|encrypt(sender_cert, msg)]
                  signature.sign - the signature
*/
void generate_message(string username, unordered_map<string, int>& idmap) {
    
    // get pub key and use the pub key to encrypt the key for symmetric encryption
    system("openssl x509 -pubkey -noout -in tmp/recipient.cert.pem > tmp/recipient.pubkey.pem");
    system("openssl rand -base64 32 > tmp/key.bin"); // generate random key for symmetric encryption
    system("openssl rsautl -encrypt -pubin -inkey tmp/recipient.pubkey.pem -in tmp/key.bin -out tmp/key.bin.enc");
    
    // use symmetric encryption to encrypt the file
    system("openssl enc -aes-256-cbc -salt -in tmp/cert_msg -out tmp/cert_msg.enc -pass file:tmp/key.bin");
    
    // add id before
    if (!idmap.count(username)) idmap[username] = 0;
    ofstream out("tmp/id_mail.enc", ofstream::binary);
    ifstream message("tmp/cert_msg.enc", ifstream::binary);
    out << ++idmap[username] << endl << message.rdbuf();
    message.close();
    out.close();

    // sign the [id|encrypt(sender_cert, msg)]
    system(("openssl dgst -sha256 -sign " + key_path + " -out tmp/signature.sign tmp/id_mail.enc").c_str());
}

std::vector<std::string> splitStringBy(std::string s, std::string delimiter) {
    std::vector<std::string> splitted;
    std::string unparsed(s);
    size_t pos = 0;
    std::string token;
    while ((pos = unparsed.find(delimiter)) != std::string::npos) {
        token = unparsed.substr(0, pos);
        splitted.push_back(token);
        unparsed.erase(0, pos + delimiter.length());
    }
    splitted.push_back(unparsed);
    return splitted;
}

int main(int argc, const char * argv[]){

    if (argc < 3) {
        std::cerr << "Invalid number of arguments." << std::endl;
        std::cerr << "Usage: ./sendmsg RECIPIENT MESSAGEFILE" << std::endl;
        return 1;
    }

    std::vector<std::string> recipients;
    for (int i = 1; i < argc - 1; i ++) {
        std::string recipientName(argv[i]);
        recipients.push_back(recipientName);
    }
    std::string messageFile(argv[argc - 1]);


    // get the mail-id for each recipient
    ifstream idfile(id_path.c_str(), ifstream::binary);
    unordered_map<string, int> idmap;
    string recipient;
    int num;
    while(idfile >> recipient >> num){
        idmap[recipient] = num;
    }
    idfile.close();

    // generate [cert|msg]
    ifstream msg(messageFile, ifstream::binary);
    ifstream cert(cert_path, ifstream::binary);
    if (!msg) {
        cout << "Couldn't find message file." << endl;
        return 1;
    }
    if (!cert) {
        cout << "Couldn't find client certificate." << endl;
        return 1;
    }
    //system("mkdir -p tmp");
    ofstream out("tmp/cert_msg", ofstream::binary);
    out << cert.rdbuf() << endl << msg.rdbuf();
    msg.close();
    cert.close();
    out.close();

    /***** establish connection to the server*****/
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

    /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

    // edit this to trust a local certificate
    // if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
    // use the ca's certificate here
    if (SSL_CTX_load_verify_locations(ctx.get(), "ca-chain.cert.pem", nullptr) != 1) {
        my::print_errors_and_exit("Error setting up trust store");
    }

    // load config
    std::map<std::string, std::string> config_map = my::load_config();
    std::string server_url = config_map["server_ip"] + ":" + config_map["server_port"];

    // Change this line to connects to real duckduckgo
    // auto bio = my::UniquePtr<BIO>(BIO_new_connect("duckduckgo.com:443"));
    auto bio = my::UniquePtr<BIO>(BIO_new_connect(server_url.c_str()));
    if (bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }
    auto ssl_bio = std::move(bio)
                   | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1))
    ;
    SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), "duckduckgo.com");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(my::get_ssl(ssl_bio.get()), "duckduckgo.com");
#endif
    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_handshake");
    }
    my::verify_the_certificate(my::get_ssl(ssl_bio.get()), "duckduckgo.com");
    
    /***************** connection established ***********************/

    my::send_certificate(ssl_bio.get(), cert_path, "sendmsg"); // send certificate to server

    string response = my::receive_http_message(ssl_bio.get());

    // first response, number expected, if fake identity, also stored in that file
    std::string error_code = my::get_body_and_store(response, "tmp/number.enc");
    my::check_response("tmp/number.enc", error_code);

    string number = exec("openssl pkeyutl -decrypt -inkey " + key_path + " -in tmp/number.enc");
    cout << number << endl;
    my::send_number_and_recipient(ssl_bio.get(), number, recipients); // send decrypted number to server
    response = my::receive_http_message(ssl_bio.get()); // get recipient's certificate

    std::cout << response << std::endl;

    std::vector<std::string> responseLines = splitStringBy(response, "\r\n");
    std::vector<std::string> validRecipients;
    int i = 3;
    while (i + 1 <= responseLines.size() - 1) {
        std::string recipientName = responseLines[i];
        std::string cert_content = responseLines[i + 1];
        if (cert_content.find("-----BEGIN CERTIFICATE-----") != std::string::npos) {
            std::string cert_loc = "tmp/" + recipientName + ".cert.pem"
            std::ofstream rbody(cert_loc, std::ofstream::binary);
            rbody << cert_content;
            rbody.close();
            validRecipients.push_back(recipientName);
        }
        i += 2;
    }

    for (int i = 0; i < validRecipients.size(); i ++) {
        std::cout << validRecipients[i] << std::endl;
    }
    return 0;


    generate_message(argv[1], idmap);
    send_msg(ssl_bio.get(), argv[1]); // send message to server
    response = my::receive_http_message(ssl_bio.get());
    cout << response << endl;
    // update the id file

    system("rm tmp/*");

    ofstream idfile2(id_path.c_str(), ofstream::binary);
    for(auto &p: idmap){
        idfile2 << p.first << " " << p.second << endl;
    }
    idfile2.close();
}