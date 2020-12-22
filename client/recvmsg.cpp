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

const string cert_path = "client_files/cert.pem";
const string key_path = "client_files/key.pem";
const string id_path = "client_files/sender_id.txt";

// execute shell command and return the output
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

/*
parameter:  key_file: should decrypt it and then use it to decrypt msg
            id_mail.enc = [id, encrypt(cert,msg)]
            signature.sign
            sendername
            idmap
*/
void check_and_decrypt(string key_file, string id_mail_file, string sign_file, 
                       unordered_map<string, int>& idmap) {
    
    // get key for decryption from key_file
    system(("openssl rsautl -decrypt -inkey " + key_path + 
            " -in " + key_file + " -out tmp/key.dec").c_str());

    // split the id and encrypted file
    ifstream id_mail(id_mail_file.c_str(), ifstream::binary);
    ofstream encrypted("tmp/mail.enc", ofstream::binary);
    string id;
    getline(id_mail, id);
    encrypted << id_mail.rdbuf();
    id_mail.close();
    encrypted.close();
    
    // decrypt file
    system("openssl enc -d -aes-256-cbc -in tmp/mail.enc -out tmp/mail.dec -pass file:tmp/key.dec");

    // split decrypted to [cert, msg]
    ifstream decrypted("tmp/mail.dec", ifstream::binary);
    ofstream cert("tmp/sender.cert.pem", ofstream::binary);
    string line;
    while(getline(decrypted, line)){
        if (line.size()) cert << line << endl;
        else break;
    }
    cout << decrypted.rdbuf();
    cert.close();
    decrypted.close();

    // check sender's cert
    if (exec("openssl verify -CAfile ca-chain.cert.pem tmp/sender.cert.pem") != "tmp/sender.cert.pem: OK") {
        cout << "Sender's certificate is not verified" << endl;
        return;
    }

    // check id
    string subname = exec("openssl x509 -noout -subject -in tmp/sender.cert.pem");
    string sendername = subname.substr(subname.rfind(" ") + 1);
    if (!idmap.count(sendername)) idmap[sendername]=0;
    if (++idmap[sendername] != stoi(id)) {
        cout << "id corrupted. " << endl;
        // TODO: return
        //return;
    }

    // get pub key from cert and check signiture
    system("openssl x509 -pubkey -noout -in tmp/sender.cert.pem > tmp/sender.pubkey.pem");
    if (exec("openssl dgst -sha256 -verify tmp/sender.pubkey.pem -signature " +
            sign_file + " " + id_mail_file) != "Verified OK") {
            cout << "Mail corrupted." << endl;
            return;
    }

    // clear intermediate files
    system("rm tmp/*");
}

int main(){
    // get the mail-id for each sender
    ifstream idfile(id_path.c_str(), ifstream::binary);
    unordered_map<string, int> idmap;
    string recipient;
    int num;
    while(idfile >> recipient >> num){
        idmap[recipient] = num;
    }
    idfile.close();

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
    auto bio = my::UniquePtr<BIO>(BIO_new_connect(server_url));
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

    my::send_certificate(ssl_bio.get(), cert_path, "recvmsg");

    string response = my::receive_http_message(ssl_bio.get());
    std::string error_code = my::get_body_and_store(response, "tmp/sav.number.enc");
    my::check_response("tmp/sav.number.enc", error_code);
    string number = exec("openssl pkeyutl -decrypt -inkey " + key_path + " -in tmp/sav.number.enc");
    cout << number << endl;
    my::send_number(ssl_bio.get(), number); // send decrypted number to server
    
    response = my::receive_http_message(ssl_bio.get()); // get key.enc
    //cout << response << endl;
    error_code = my::get_body_and_store(response, "tmp/sav.key.bin.enc");
    my::check_response("tmp/sav.key.bin.enc", error_code);

    response = my::receive_http_message(ssl_bio.get()); // get id_mail.enc
    //cout << response << endl;
    my::get_body_and_store(response, "tmp/sav.id_mail.enc");    

    response = my::receive_http_message(ssl_bio.get()); // get key.enc
    //cout << response << endl;
    my::get_body_and_store(response, "tmp/sav.signature.sign");  

    // get 3 files: key.bin.enc id_mail.enc signature.sign
    check_and_decrypt("tmp/sav.key.bin.enc", "tmp/sav.id_mail.enc", "tmp/sav.signature.sign", idmap);

    // update the id file
    ofstream idfile2(id_path.c_str(), ofstream::binary);
    for(auto &p: idmap){
        idfile2 << p.first << " " << p.second << endl;
    }
    idfile2.close();
}