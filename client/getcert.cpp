// Usage: ./getcert username password

#include "client_helper.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string>
#include <fstream>
#include <map>

std::string read_csr(std::string csr_path) {
    std::ifstream ifs(csr_path);
    std::string content( (std::istreambuf_iterator<char>(ifs) ),
                         (std::istreambuf_iterator<char>()    ) );
    return content;
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        std::cerr << "Invalid number of arguments." << std::endl;
        std::cerr << "Usage: ./getcert USERNAME PASSWORD" << std::endl;
        return 1;
    }

    std::string username(argv[1]);
    if (!my::is_username_valid(username)) {
        std::cerr << "username is not correctly formatted." << std::endl;
        return 1;
    }

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

    system(("./cgencsr.sh "+username).c_str());
    std::string password(argv[2]);
    std::string csr_content = read_csr("client_files/csr.pem");
    my::send_getcert_request(ssl_bio.get(), username, password, csr_content);
    std::string response = my::receive_http_message(ssl_bio.get());

    size_t pos = response.find("-----BEGIN CERTIFICATE-----");
    if (pos != std::string::npos) {
        std::string certificate = response.substr(pos, response.size() - pos);
        std::ofstream out("client_files/cert.pem");
        out << certificate;
        out.close();
        std::cout << "successfully got certificate, saved at client_files/cert.pem" << std::endl;
    } else {
        std::cout << "failed to get certificate" << std::endl;
    }
}
