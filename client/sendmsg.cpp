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

const string cert_path = "cindy.cert.pem";
const string key_path = "cindy.key.pem";
const string id_path = "recipient_id.txt";

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
    stringstream ss(response);
    string temp;
    getline(ss,temp);
    getline(ss,temp);
    getline(ss,temp);
    ofstream rbody(loc.c_str(), ofstream::binary);
    rbody << ss.rdbuf();
    rbody.close();
}

void send_certificate(BIO *bio) {
    ifstream cert(cert_path, ifstream::binary);
    string c((istreambuf_iterator<char>(cert)), istreambuf_iterator<char>());
    cert.close();

    string fields = "type=sendmsg&step=cert&cert=" + c;
    string request = "POST / HTTP/1.1\r\n";
    request += "Host: duckduckgo.com\r\n";
    request += "Content-Type: text/plain\r\n";
    request += "Content-Length: " + to_string(fields.size()) + "\r\n";
    request += "\r\n";
    request += fields + "\r\n";
    request += "\r\n";
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void send_number_and_recipient(BIO *bio, const string & response, string recipient) {
    // decrypt number from response
    get_body_and_store(response, "temp.number");
    string number = exec("openssl pkeyutl -decrypt -inkey " + key_path + " -in temp.number");
    remove("temp.number");
    string fields = "type=sendmsg&step=number&number=" + number + "&recipient=bob";
    string request = "POST / HTTP/1.1\r\n";
    request += "Host: duckduckgo.com\r\n";
    request += "Content-Type: text/plain\r\n";
    request += "Content-Length: " + to_string(fields.size()) + "\r\n";
    request += "\r\n";
    request += fields + "\r\n";
    request += "\r\n";
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void send_msg(BIO *bio, string recipient) {
    ifstream f1("key.bin.enc", ifstream::binary);
    string keyenc((std::istreambuf_iterator<char>(f1)), std::istreambuf_iterator<char>());
    f1.close();
    ifstream f2("id_mail.enc", ifstream::binary);
    string idmail((std::istreambuf_iterator<char>(f2)), std::istreambuf_iterator<char>());
    f2.close();
    ifstream f3("signature.sign", ifstream::binary);
    string sg((std::istreambuf_iterator<char>(f3)), std::istreambuf_iterator<char>());
    f3.close();

    string fields = "type=sendmsg&step=recipient&recipient=" + recipient + "&msg=" 
                 + keyenc + "\n\n" + idmail + "\n\n" + sg;
    string request = "POST / HTTP/1.1\r\n";
    request += "Host: duckduckgo.com\r\n";
    request += "Content-Type: text/plain\r\n";
    request += "Content-Length: " + to_string(fields.size()) + "\r\n";
    request += "\r\n";
    request += fields + "\r\n";
    request += "\r\n";
    cout << request << endl;
    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

/*
parameter:  username: recipient name
            message_file = sender_cert + message
            idmap: the ID (number) of the mail for the recipient
output: 3 files:  key.bin.enc - the key used for symmetric encryption
                  id_mail.enc - [id|encrypt(sender_cert, msg)]
                  signature.sign - the signature
*/
void generate_message(string username, string message_file, unordered_map<string, int>& idmap) {
    
    // get pub key and use the pub key to encrypt the key for symmetric encryption
    system(("openssl x509 -pubkey -noout -in " + username + ".cert.pem > temp.pubkey.pem").c_str());
    system("openssl rand -base64 32 > key.bin");
    system("openssl rsautl -encrypt -pubin -inkey temp.pubkey.pem -in key.bin -out key.bin.enc");
    
    // use symmetric encryption to encrypt the file
    system(("openssl enc -des3 -pbkdf2 -salt -in " + message_file
            + " -out temp.enc -pass file:./key.bin").c_str());

    // add id before
    if (!idmap.count(username)) idmap[username] = 0;
    ofstream out("id_mail.enc", ofstream::binary);
    ifstream message("temp.enc", ifstream::binary);
    out << ++idmap[username] << endl << message.rdbuf() << endl;
    message.close();
    out.close();

    // sign the [id|encrypt(sender_cert, msg)]
    system(("openssl dgst -sha256 -sign " + key_path + " -out signature.sign id_mail.enc").c_str());

    // clear intermediate file    
    //system("rm key.bin temp.enc temp.pubkey.pem");
}

int main(){
    
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
    ofstream out("testMessage.txt", ofstream::binary);
    ifstream cert(cert_path, ifstream::binary);
    ifstream msg("MessageText.txt", ifstream::binary);
    out << cert.rdbuf() << endl << msg.rdbuf();
    msg.close();
    cert.close();
    out.close();

    /***** the following is to establish connection to the server and send certificate *****/

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
    if (SSL_CTX_load_verify_locations(ctx.get(), "ca-cert.pem", nullptr) != 1) {
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

    send_certificate(ssl_bio.get());
    string response = my::receive_http_message(ssl_bio.get());

    /********* establish connection again and send number and recipient ************/

    bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
    if (bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }
    ssl_bio = std::move(bio)
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

    send_number_and_recipient(ssl_bio.get(), response, "bob");
    response = my::receive_http_message(ssl_bio.get());
    get_body_and_store(response, "bob.cert.pem");

    /***  above all is to get recipient certificate and store to recipient.cert.pem ***/

    generate_message("bob", "testMessage.txt", idmap);

    system("rm -rf testMessage.txt");
    /********* establish connection again and send 3 parts of the message ************/

    bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
    if (bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }
    ssl_bio = std::move(bio)
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

    send_msg(ssl_bio.get(), "bob");
    //response = my::receive_http_message(ssl_bio.get());

    // update the id file
    ofstream idfile2(id_path.c_str(), ofstream::binary);
    for(auto &p: idmap){
        idfile2 << p.first << " " << p.second << endl;
    }
    idfile2.close();
}