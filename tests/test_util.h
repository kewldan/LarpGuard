#ifndef BOT_SHIELD_TESTS_TEST_UTIL_H_
#define BOT_SHIELD_TESTS_TEST_UTIL_H_

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>  // IWYU pragma: keep (ssize_t on Linux)
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace bot_shield::testing {

struct TestCertificate {
  std::string cert_pem;
  std::string key_pem;
};

// Self-signed P-256 certificate with the given DNS SANs.
TestCertificate MakeCertificate(const std::vector<std::string>& dns_names,
                                int64_t valid_seconds = int64_t{30} * 24 *
                                                        3600);

std::string Base64(std::string_view data);

// acme.json in Traefik's layout with every certificate under one resolver.
std::string MakeAcmeJson(
    const std::vector<std::pair<std::string, TestCertificate>>& certificates);

// A real ClientHello produced by BoringSSL's client.
std::vector<uint8_t> MakeClientHello(std::string_view server_name,
                                     const std::vector<std::string>& alpn);

// One-connection-at-a-time HTTP server on 127.0.0.1 for the client tests.
// `handler` maps the request head to the raw response bytes.
class TestServer {
 public:
  using Handler = std::function<std::string(const std::string& head)>;

  explicit TestServer(Handler handler, SSL_CTX* tls = nullptr)
      : handler_(std::move(handler)), tls_(tls) {
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) !=
        0) {
      return;
    }
    socklen_t size = sizeof(address);
    getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &size);
    port_ = ntohs(address.sin_port);
    listen(fd_, 8);
    thread_ = std::thread([this] { Serve(); });
  }

  ~TestServer() {
    stopping_ = true;
    shutdown(fd_, SHUT_RDWR);
    close(fd_);
    thread_.join();
  }

  TestServer(const TestServer&) = delete;
  TestServer& operator=(const TestServer&) = delete;

  int port() const { return port_; }

 private:
  void Serve() {
    while (!stopping_) {
      const int client = accept(fd_, nullptr, nullptr);
      if (client < 0) return;
      SSL* ssl = nullptr;
      if (tls_ != nullptr) {
        ssl = SSL_new(tls_);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) != 1) {
          SSL_free(ssl);
          close(client);
          continue;
        }
      }
      std::string head;
      std::array<char, 4096> buffer{};
      while (head.find("\r\n\r\n") == std::string::npos) {
        const ssize_t n =
            ssl != nullptr
                ? SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()))
                : read(client, buffer.data(), buffer.size());
        if (n <= 0) break;
        head.append(buffer.data(), static_cast<std::size_t>(n));
      }
      const std::string response = handler_(head);
      if (ssl != nullptr) {
        SSL_write(ssl, response.data(), static_cast<int>(response.size()));
        SSL_shutdown(ssl);
        SSL_free(ssl);
      } else {
        write(client, response.data(), response.size());
      }
      close(client);
    }
  }

  Handler handler_;
  SSL_CTX* tls_;
  int fd_ = -1;
  int port_ = 0;
  std::atomic<bool> stopping_{false};
  std::thread thread_;
};

}  // namespace bot_shield::testing

#endif  // BOT_SHIELD_TESTS_TEST_UTIL_H_
