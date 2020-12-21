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

void get_body_and_store(const string & response, const string & loc) {
    //cout << response << endl;
    stringstream ss(response);
    string temp;
    getline(ss,temp);
    getline(ss,temp);
    getline(ss,temp);
    ofstream rbody(loc.c_str(), ofstream::binary);
    rbody << ss.rdbuf();
    rbody.close();
}

void check_recipient_cert(const string & loc) {
    ifstream f(loc);
    string s;
    f >> s;
    f.close();
    if (s == "Fake") {
        cout << "Fake identity!" << endl;
        exit(1);
    }
    cout << "Identity confirmed!" << endl;
}

string generate_header(int bodylen) {
    string request = "POST / HTTP/1.1\r\n";
    request += "Host: duckduckgo.com\r\n";
    request += "Content-Type: application/octet-stream\r\n";
    request += "Content-Length: " + to_string(bodylen) + "\r\n";
    request += "\r\n";
    return request;
}

void send_certificate(BIO *bio) {
    ifstream cert(cert_path, ifstream::binary);
    string c((istreambuf_iterator<char>(cert)), istreambuf_iterator<char>());
    cert.close();
    string fields = "type=sendmsg&cert=" + c;
    string request = generate_header(fields.size());
    request += fields + "\r\n";
    request += "\r\n";
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void send_number_and_recipient(BIO *bio, const string & number, string recipient) {
    string fields = number + "&" + recipient;
    string request = generate_header(fields.size());
    request += fields + "\r\n";
    request += "\r\n";
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

    string fields = keyenc + "\n\n" + idmail + "\n\n" + sg;
    string request = generate_header(fields.size());
    request += fields + "\r\n";
    request += "\r\n";
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
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
    system("openssl enc -des3 -pbkdf2 -salt -in tmp/cert_msg -out tmp/cert_msg.enc -pass file:tmp/key.bin");

    // add id before
    if (!idmap.count(username)) idmap[username] = 0;
    ofstream out("tmp/id_mail.enc", ofstream::binary);
    ifstream message("tmp/cert_msg.enc", ifstream::binary);
    out << ++idmap[username] << endl << message.rdbuf() << endl;
    message.close();
    out.close();

    // sign the [id|encrypt(sender_cert, msg)]
    system(("openssl dgst -sha256 -sign " + key_path + " -out tmp/signature.sign tmp/id_mail.enc").c_str());
}

int main(int argc, const char * argv[]){
    if (argc != 3) {
        cout << "Please apply the recipient name and your message file path" << endl;
        return 1;
    }

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
    ifstream msg(argv[2], ifstream::binary);
    ifstream cert(cert_path, ifstream::binary);
    if (!msg) {
        cout << "Couldn't find message file." << endl;
        return 1;
    }
    if (!cert) {
        cout << "Couldn't find client certificate." << endl;
        return 1;
    }
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

    // Change this line to connects to real duckduckgo
    // auto bio = my::UniquePtr<BIO>(BIO_new_connect("duckduckgo.com:443"));
    auto bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
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

    send_certificate(ssl_bio.get()); // send certificate to server

    string response = my::receive_http_message(ssl_bio.get());

    system("mkdir -p tmp");
    get_body_and_store(response, "tmp/number.enc");
    string number = exec("openssl pkeyutl -decrypt -inkey " + key_path + " -in tmp/number.enc");
    cout << number << endl;
    send_number_and_recipient(ssl_bio.get(), number, argv[1]); // send decrypted number to server
    response = my::receive_http_message(ssl_bio.get()); // get recipient's certificate
    get_body_and_store(response, "tmp/recipient.cert.pem");
    check_recipient_cert("tmp/recipient.cert.pem");

    generate_message(argv[1], idmap);
    send_msg(ssl_bio.get(), argv[1]); // send message to server
    response = my::receive_http_message(ssl_bio.get());
    cout << response << endl;
    // update the id file
    ofstream idfile2(id_path.c_str(), ofstream::binary);
    for(auto &p: idmap){
        idfile2 << p.first << " " << p.second << endl;
    }
    idfile2.close();
}