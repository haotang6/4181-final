// Usage: ./getcert username password

#include "client_helper.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string>

std::string read_csr(std::string csr_path) {
    std::string content( (std::istreambuf_iterator<char>(ifs) ),
                         (std::istreambuf_iterator<char>()    ) );
    return content;
}

int main(int argc, char *argv[]) {

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

    std::string username(argv[1]);
    std::string password(argv[2]);
    std::string csr_path(argv[3]);
    std::string csr_content = read_csr(csr_path);
    my::send_getcert_request(ssl_bio.get(), username, password, csr_content);
    std::string response = my::receive_http_message(ssl_bio.get());
    printf("%s", response.c_str());

}
