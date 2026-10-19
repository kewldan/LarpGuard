#include "net/http_client.h"

#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/types.h>  // IWYU pragma: keep (ssize_t on Linux)
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>

#include "common/compress.h"
#include "test_util.h"

namespace bot_shield {
namespace {

TEST(ParseUrlTest, SplitsParts) {
  ParsedUrl url;
  ASSERT_TRUE(ParseUrl("https://example.com/a/b?c=1", &url));
  EXPECT_TRUE(url.tls);
  EXPECT_EQ(url.host, "example.com");
  EXPECT_EQ(url.port, "443");
  EXPECT_EQ(url.target, "/a/b?c=1");
  ASSERT_TRUE(ParseUrl("http://[::1]:8080", &url));
  EXPECT_FALSE(url.tls);
  EXPECT_EQ(url.host, "::1");
  EXPECT_EQ(url.port, "8080");
  EXPECT_EQ(url.target, "/");
  ASSERT_TRUE(ParseUrl("https://h?q", &url));
  EXPECT_EQ(url.target, "/?q");
  EXPECT_FALSE(ParseUrl("ftp://x/", &url));
  EXPECT_FALSE(ParseUrl("https://user@x/", &url));
  EXPECT_FALSE(ParseUrl("https://x:99999999/", &url));
  EXPECT_FALSE(ParseUrl("https:///", &url));
}

TEST(CompressTest, GunzipsAndLimits) {
  // gzip of "hello, larpguard\n" x 3 (Python gzip.compress, mtime 0).
  constexpr std::array<unsigned char, 40> kGzip = {
      0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
      0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0xc8, 0x49, 0x2c,
      0x2a, 0x48, 0x2f, 0x4d, 0x2c, 0x4a, 0xe1, 0xca, 0x20, 0x28,
      0x00, 0x00, 0x96, 0xd7, 0x27, 0x3e, 0x33, 0x00, 0x00, 0x00};
  const std::string_view data(reinterpret_cast<const char*>(kGzip.data()),
                              kGzip.size());
  std::string out;
  std::string error;
  ASSERT_TRUE(Gunzip(data, 1000, &out, &error)) << error;
  EXPECT_EQ(out, "hello, larpguard\nhello, larpguard\nhello, larpguard\n");
  EXPECT_FALSE(Gunzip(data, 10, &out, &error));
  EXPECT_FALSE(Gunzip(data.substr(0, 20), 1000, &out, &error));
  EXPECT_FALSE(Gunzip("not gzip", 1000, &out, &error));
  EXPECT_EQ(Crc32("123456789"), 0xCBF43926U);
}

std::string Respond(const std::string& head) {
  if (head.starts_with("GET /plain ")) {
    return "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello";
  }
  if (head.starts_with("GET /chunked ")) {
    return "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
  }
  if (head.starts_with("GET /close ")) {
    return "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close";
  }
  if (head.starts_with("GET /redirect ")) {
    return "HTTP/1.1 302 Found\r\nLocation: /plain\r\nContent-Length: 0"
           "\r\n\r\n";
  }
  if (head.starts_with("GET /loop ")) {
    return "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n";
  }
  if (head.starts_with("POST /echo ")) {
    const std::size_t body = head.find("\r\n\r\n") + 4;
    const std::string content = head.substr(body);
    return std::format("HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n{}",
                       content.size(), content);
  }
  if (head.starts_with("GET /big ")) {
    return "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" +
           std::string(100, 'x');
  }
  return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
}

TEST(HttpClientTest, PlainHttp) {
  testing::TestServer server(Respond);
  const std::string base = std::format("http://127.0.0.1:{}", server.port());
  HttpClientRequest request;
  HttpClientResponse response;
  std::string error;

  request.url = base + "/plain";
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.body, "hello");
  EXPECT_EQ(response.Header("x-test"), "yes");

  request.url = base + "/chunked";
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.body, "abcde");

  request.url = base + "/close";
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.body, "until close");

  request.url = base + "/redirect";
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.body, "hello");

  request.url = base + "/loop";
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.status, 302);  // Gave up after max_redirects.

  request.url = base + "/missing";
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.status, 404);

  request.url = base + "/big";
  request.max_body = 10;
  EXPECT_FALSE(HttpFetch(request, &response, &error));
  EXPECT_NE(error.find("too large"), std::string::npos) << error;
}

TEST(HttpClientTest, PostSendsBody) {
  // The test server reads only up to the end of the head plus whatever came
  // with it; a short body arrives in the same segment.
  testing::TestServer server(Respond);
  HttpClientRequest request;
  request.method = "POST";
  request.url = std::format("http://127.0.0.1:{}/echo", server.port());
  request.headers = {{"Content-Type", "application/x-www-form-urlencoded"}};
  request.body = "secret=a&response=b";
  HttpClientResponse response;
  std::string error;
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.status, 201);
  EXPECT_EQ(response.body, "secret=a&response=b");
}

TEST(HttpClientTest, ConnectErrorAndTimeout) {
  HttpClientRequest request;
  HttpClientResponse response;
  std::string error;
  {
    // Bound but never answering: the deadline fires.
    testing::TestServer server([](const std::string&) {
      std::this_thread::sleep_for(std::chrono::milliseconds(800));
      return std::string();
    });
    request.url = std::format("http://127.0.0.1:{}/slow", server.port());
    request.timeout = std::chrono::milliseconds(200);
    EXPECT_FALSE(HttpFetch(request, &response, &error));
    EXPECT_NE(error.find("timed out"), std::string::npos) << error;
  }
  request.url = "http://127.0.0.1:1/";
  request.timeout = std::chrono::milliseconds(2000);
  EXPECT_FALSE(HttpFetch(request, &response, &error));
}

TEST(HttpClientTest, HttpsVerifiesTheServer) {
  const testing::TestCertificate certificate =
      testing::MakeCertificate({"localhost"});
  bssl::UniquePtr<SSL_CTX> tls(SSL_CTX_new(TLS_server_method()));
  bssl::UniquePtr<BIO> cert_bio(
      BIO_new_mem_buf(certificate.cert_pem.data(),
                      static_cast<int>(certificate.cert_pem.size())));
  bssl::UniquePtr<X509> cert(
      PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(certificate.key_pem.data(),
                      static_cast<int>(certificate.key_pem.size())));
  bssl::UniquePtr<EVP_PKEY> key(
      PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(cert && key);
  SSL_CTX_use_certificate(tls.get(), cert.get());
  SSL_CTX_use_PrivateKey(tls.get(), key.get());
  testing::TestServer server(Respond, tls.get());

  const std::filesystem::path ca =
      std::filesystem::temp_directory_path() /
      std::format("bs-http-client-ca-{}.pem", getpid());
  std::ofstream(ca) << certificate.cert_pem;
  SetHttpClientCaFile(ca.string());

  HttpClientRequest request;
  HttpClientResponse response;
  std::string error;
  request.url = std::format("https://localhost:{}/plain", server.port());
  ASSERT_TRUE(HttpFetch(request, &response, &error)) << error;
  EXPECT_EQ(response.body, "hello");

  // Same server, a name the certificate does not cover.
  request.url = std::format("https://127.0.0.1:{}/plain", server.port());
  EXPECT_FALSE(HttpFetch(request, &response, &error));

  // A CA that did not sign it.
  const testing::TestCertificate other = testing::MakeCertificate({"x"});
  std::ofstream(ca) << other.cert_pem;
  request.url = std::format("https://localhost:{}/plain", server.port());
  EXPECT_FALSE(HttpFetch(request, &response, &error));

  SetHttpClientCaFile("");
  std::filesystem::remove(ca);
}

}  // namespace
}  // namespace bot_shield
