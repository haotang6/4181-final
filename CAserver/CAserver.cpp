#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <map>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

// sudo apt install whois

namespace my {

    template<class T> struct DeleterOf;
    template<> struct DeleterOf<BIO> { void operator()(BIO *p) const { BIO_free_all(p); } };
    template<> struct DeleterOf<BIO_METHOD> { void operator()(BIO_METHOD *p) const { BIO_meth_free(p); } };
    template<> struct DeleterOf<SSL_CTX> { void operator()(SSL_CTX *p) const { SSL_CTX_free(p); } };

    template<class OpenSSLType>
    using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

    my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper)
    {
        BIO_push(upper.get(), lower.release());
        return upper;
    }

    class StringBIO {
        std::string str_;
        my::UniquePtr<BIO_METHOD> methods_;
        my::UniquePtr<BIO> bio_;
    public:
        StringBIO(StringBIO&&) = delete;
        StringBIO& operator=(StringBIO&&) = delete;

        explicit StringBIO() {
            methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
            if (methods_ == nullptr) {
                throw std::runtime_error("StringBIO: error in BIO_meth_new");
            }
            BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
                std::string *str = reinterpret_cast<std::string*>(BIO_get_data(bio));
                str->append(data, len);
                return len;
            });
            bio_.reset(BIO_new(methods_.get()));
            if (bio_ == nullptr) {
                throw std::runtime_error("StringBIO: error in BIO_new");
            }
            BIO_set_data(bio_.get(), &str_);
            BIO_set_init(bio_.get(), 1);
        }
        BIO *bio() { return bio_.get(); }
        std::string str() && { return std::move(str_); }
    };

    [[noreturn]] void print_errors_and_exit(const char *message)
    {
        fprintf(stderr, "%s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    [[noreturn]] void print_errors_and_throw(const char *message)
    {
        my::StringBIO bio;
        ERR_print_errors(bio.bio());
        throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
    }

    std::string receive_some_data(BIO *bio)
    {
        char buffer[1024];
        int len = BIO_read(bio, buffer, sizeof(buffer));
        if (len < 0) {
            my::print_errors_and_throw("error in BIO_read");
        } else if (len > 0) {
            return std::string(buffer, len);
        } else if (BIO_should_retry(bio)) {
            return receive_some_data(bio);
        } else {
            my::print_errors_and_throw("empty BIO_read");
        }
    }

    std::vector<std::string> split_headers(const std::string& text)
    {
        std::vector<std::string> lines;
        const char *start = text.c_str();
        while (const char *end = strstr(start, "\r\n")) {
            lines.push_back(std::string(start, end));
            start = end + 2;
        }
        return lines;
    }

    std::string receive_http_message(BIO *bio)
    {
        std::string headers = my::receive_some_data(bio);
        char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
        while (end_of_headers == nullptr) {
            headers += my::receive_some_data(bio);
            end_of_headers = strstr(&headers[0], "\r\n\r\n");
        }
        std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
        headers.resize(end_of_headers+2 - &headers[0]);
        size_t content_length = 0;
        for (const std::string& line : my::split_headers(headers)) {
            if (const char *colon = strchr(line.c_str(), ':')) {
                auto header_name = std::string(&line[0], colon);
                if (header_name == "Content-Length") {
                    content_length = std::stoul(colon+1);
                }
            }
        }
        while (body.size() < content_length) {
            body += my::receive_some_data(bio);
        }
        return headers + "\r\n" + body;
    }

    void send_http_response(BIO *bio, const std::string& body)
    {
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        response += "\r\n";

        BIO_write(bio, response.data(), response.size());
        BIO_write(bio, body.data(), body.size());
        BIO_flush(bio);
    }

    std::map<std::string, std::string> load_password_database()
    {
        std::map<std::string, std::string> password_db;
        std::ifstream in("user_passwords.txt");
        std::string str;
        while (std::getline(in, str))
        {
            if(str.size() > 0)
            {
                size_t pos = str.find(" ");
                password_db[str.substr(0, pos)] = str.substr(pos + 1, str.size() - pos - 1);
            }
        }
        return password_db;
    }

    void save_password_database(std::map<std::string, std::string> password_db)
    {
        std::ofstream out("user_passwords.txt");
        for (auto const& x: password_db) {
            out << x.first;
            out << " ";
            out << x.second;
            out << "\n";
        }
        out.close();
    }

    void save_csr_to_tmp(std::string username, std::string csr_content)
    {
        std::ofstream out("tmp/" + username + ".csr.pem");
        out << csr_content;
        out.close();
    }

    std::string hash_password(std::string password)
    {
        std::array<char, 128> buffer;
        std::string result;
        std::string command = "mkpasswd --method=sha512crypt --salt=5Q91hyuzJvXqU67r \"" + password + "\"";
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            throw std::runtime_error("popen() failed!");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result;
    }

    void sign_certificate(std::string username, std::string csr_path)
    {
        std::string command = "./sgencert.sh " + username + " " + csr_path;
        system(command.c_str());
    }

    std::string read_certificate(std::string cert_path)
    {
        std::ifstream ifs(cert_path);
        std::string cert_content( (std::istreambuf_iterator<char>(ifs) ),
                                  (std::istreambuf_iterator<char>()    ) );
        return cert_content;
    }

    my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
    {
        if (BIO_do_accept(accept_bio) <= 0) {
            return nullptr;
        }
        return my::UniquePtr<BIO>(BIO_pop(accept_bio));
    }

} // namespace my

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

int main()
{

    std::map<std::string, std::string> password_db = my::load_password_database();
    std::cout << "loading users from database..." << std::endl;
    for(auto itr = password_db.begin(); itr != password_db.end(); itr++) {
        std::cout << itr->first << std::endl;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#endif

    if (SSL_CTX_use_certificate_file(ctx.get(), "caserver.cert.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "caserver.key.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server private key");
    }

    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("10086"));
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port 10086)");
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });
    while (auto bio = my::accept_new_tcp_connection(accept_bio.get())) {
        bio = std::move(bio)
              | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0))
                ;
        try {
            std::string request = my::receive_http_message(bio.get());
            printf("Got request:\n");
            std::vector<std::string> requestLines = splitStringBy(request, "\r\n");
            std::map<std::string, std::string> paramMap;
            std::vector<std::string> params = splitStringBy(requestLines[5], "&");
            for (int i = 0; i < params.size(); i ++) {
                std::vector <std::string> kv = splitStringBy(params[i], "=");
                paramMap[kv[0]] = kv[1];
            }

            std::string csr = "";
            for (int i = 6; i < requestLines.size(); i ++) {
                csr += requestLines[i];
            }
            my::save_csr_to_tmp(paramMap["username"], csr);

            if (paramMap["type"].compare("getcert") == 0) {
                std::cout << "getcert request received from user " << paramMap["username"] << std::endl;
                std::cout << "provided password " + paramMap["password"] << std::endl;
                if (password_db.find(paramMap["username"]) == password_db.end()) {
                    my::send_http_response(bio.get(), "user not in system.\n");
                } else {
                    std::string hashedPassword = my::hash_password(paramMap["password"]);
                    password_db[paramMap["username"]] = hashedPassword;
                    my::save_password_database(password_db);
                    my::sign_certificate(paramMap["username"], "tmp/" + paramMap["username"] + ".csr.pem");
                    std::cout << "../ca/intermediate/certs/" + paramMap["username"] + ".cert.pem" << "\n";
                    my::send_http_response(bio.get(),
                        my::read_certificate("../ca/intermediate/certs/" + paramMap["username"] + ".cert.pem"));
                }
            } else if (paramMap["type"].compare("changepw") == 0) {
                std::cout << "changepw request received from user " << paramMap["username"] << std::endl;
                std::cout << "provided old password " + paramMap["old_password"] << std::endl;
                std::string hashedOldPw = my::hash_password(paramMap["old_password"]);
                if (password_db.find(paramMap["username"]) == password_db.end() ||
                    password_db[paramMap["username"]] != hashedOldPw) {
                    std::cout << "change password failed." << std::endl;
                    my::send_http_response(bio.get(), "failed request.\n");
                } else {
                    std::cout << "change password success." << std::endl;
                    password_db[paramMap["username"]] = my::hash_password(paramMap["new_password"]);
                    my::save_password_database(password_db);
                    my::send_http_response(bio.get(), "password updated.\n");
                }
            } else {
                my::send_http_response(bio.get(), "unimplemented request type\n");
            }
        } catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}
