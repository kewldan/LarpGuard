#include "net/http_client.h"

#include <llhttp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/connect.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl/context.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/ssl/stream_base.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <format>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/version.h"

namespace bot_shield {
namespace {

std::mutex& CaMutex() {
  static std::mutex mutex;
  return mutex;
}

std::string& CaFile() {
  static std::string path;
  return path;
}

std::string FindCaFile() {
  {
    const std::scoped_lock lock(CaMutex());
    if (!CaFile().empty()) return CaFile();
  }
  static constexpr std::array<std::string_view, 5> kCandidates = {
      "/etc/ssl/certs/ca-certificates.crt",  // Debian, Ubuntu, Alpine.
      "/etc/pki/tls/certs/ca-bundle.crt",    // Fedora, RHEL.
      "/etc/ssl/cert.pem",                   // macOS, BSDs.
      "/opt/homebrew/etc/ca-certificates/cert.pem",
      "/usr/local/etc/ca-certificates/cert.pem"};
  std::error_code ignored;
  for (const std::string_view candidate : kCandidates) {
    if (std::filesystem::is_regular_file(candidate, ignored)) {
      return std::string(candidate);
    }
  }
  return {};
}

std::string Lower(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

// HTTP/1.1 response collected with llhttp.
struct ResponseParser {
  explicit ResponseParser(std::size_t limit) : max_body(limit) {
    llhttp_settings_init(&settings);
    settings.on_header_field = [](llhttp_t* parser, const char* at,
                                  std::size_t size) {
      auto* self = static_cast<ResponseParser*>(parser->data);
      if (!self->in_field) {
        self->headers.emplace_back();
        self->in_field = true;
      }
      self->headers.back().first.append(at, size);
      return 0;
    };
    settings.on_header_value = [](llhttp_t* parser, const char* at,
                                  std::size_t size) {
      auto* self = static_cast<ResponseParser*>(parser->data);
      self->in_field = false;
      if (!self->headers.empty()) self->headers.back().second.append(at, size);
      return 0;
    };
    settings.on_body = [](llhttp_t* parser, const char* at, std::size_t size) {
      auto* self = static_cast<ResponseParser*>(parser->data);
      if (self->body.size() + size > self->max_body) {
        self->too_large = true;
        return -1;
      }
      self->body.append(at, size);
      return 0;
    };
    settings.on_message_complete = [](llhttp_t* parser) {
      static_cast<ResponseParser*>(parser->data)->complete = true;
      return 0;
    };
    llhttp_init(&parser, HTTP_RESPONSE, &settings);
    parser.data = this;
  }

  ResponseParser(const ResponseParser&) = delete;
  ResponseParser& operator=(const ResponseParser&) = delete;

  llhttp_settings_t settings{};
  llhttp_t parser{};
  std::vector<std::pair<std::string, std::string>> headers;
  bool in_field = false;
  std::string body;
  std::size_t max_body;
  bool too_large = false;
  bool complete = false;
};

template <typename Stream>
asio::awaitable<void> Transfer(Stream& stream, const std::string& wire,
                               ResponseParser* response, std::string* error) {
  auto [write_error, written] = co_await asio::async_write(
      stream, asio::buffer(wire), asio::as_tuple(asio::use_awaitable));
  if (write_error) {
    *error = std::format("send: {}", write_error.message());
    co_return;
  }
  std::array<char, 16384> buffer{};
  while (!response->complete) {
    auto [read_error, n] = co_await stream.async_read_some(
        asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
    if (n > 0) {
      const llhttp_errno_t parse_error =
          llhttp_execute(&response->parser, buffer.data(), n);
      if (parse_error != HPE_OK && parse_error != HPE_PAUSED) {
        *error = response->too_large
                     ? "response too large"
                     : std::format("bad HTTP response ({})",
                                   llhttp_errno_name(parse_error));
        co_return;
      }
    }
    if (read_error) {
      // A close-delimited body ends with the connection. TLS peers often
      // close without close_notify (stream_truncated).
      if (read_error == asio::error::eof ||
          read_error == asio::ssl::error::stream_truncated) {
        llhttp_finish(&response->parser);
      }
      break;
    }
  }
  if (!response->complete) *error = "incomplete response";
}

asio::awaitable<void> FetchOnce(asio::ssl::context* tls, const ParsedUrl& url,
                                const std::string& wire,
                                ResponseParser* response, std::string* error) {
  const auto executor = co_await asio::this_coro::executor;
  asio::ip::tcp::resolver resolver(executor);
  auto [resolve_error, endpoints] = co_await resolver.async_resolve(
      url.host, url.port, asio::as_tuple(asio::use_awaitable));
  if (resolve_error) {
    *error = std::format("resolve {}: {}", url.host, resolve_error.message());
    co_return;
  }
  asio::ip::tcp::socket socket(executor);
  auto [connect_error, endpoint] = co_await asio::async_connect(
      socket, endpoints, asio::as_tuple(asio::use_awaitable));
  if (connect_error) {
    *error = std::format("connect {}:{}: {}", url.host, url.port,
                         connect_error.message());
    co_return;
  }
  if (!url.tls) {
    co_await Transfer(socket, wire, response, error);
    co_return;
  }
  asio::ssl::stream<asio::ip::tcp::socket&> stream(socket, *tls);
  SSL* ssl = stream.native_handle();
  std::error_code address_error;
  asio::ip::make_address(url.host, address_error);
  X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
  if (address_error) {
    SSL_set_tlsext_host_name(ssl, url.host.c_str());
    X509_VERIFY_PARAM_set1_host(param, url.host.data(), url.host.size());
  } else {
    X509_VERIFY_PARAM_set1_ip_asc(param, url.host.c_str());
  }
  auto [handshake_error] = co_await stream.async_handshake(
      asio::ssl::stream_base::client, asio::as_tuple(asio::use_awaitable));
  if (handshake_error) {
    *error =
        std::format("TLS with {}: {}", url.host, handshake_error.message());
    co_return;
  }
  co_await Transfer(stream, wire, response, error);
}

std::string Resolve(const ParsedUrl& base, std::string_view location) {
  if (location.starts_with("http://") || location.starts_with("https://")) {
    return std::string(location);
  }
  std::string origin =
      std::format("{}://{}", base.tls ? "https" : "http", base.host);
  if (base.port != (base.tls ? "443" : "80")) origin += ":" + base.port;
  if (location.starts_with('/')) return origin + std::string(location);
  const std::string_view target = base.target;
  const std::string_view dir = target.substr(0, target.rfind('/') + 1);
  return origin + std::string(dir) + std::string(location);
}

}  // namespace

bool ParseUrl(std::string_view url, ParsedUrl* out) {
  ParsedUrl parsed;
  if (url.starts_with("https://")) {
    url.remove_prefix(8);
  } else if (url.starts_with("http://")) {
    parsed.tls = false;
    url.remove_prefix(7);
  } else {
    return false;
  }
  const std::size_t slash = url.find_first_of("/?");
  std::string_view authority = url.substr(0, slash);
  if (slash != std::string_view::npos) {
    parsed.target = std::string(url.substr(slash));
    if (parsed.target.starts_with('?')) parsed.target.insert(0, "/");
  }
  if (authority.empty() || authority.find('@') != std::string_view::npos) {
    return false;
  }
  std::string_view port;
  if (authority.starts_with('[')) {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos) return false;
    parsed.host = std::string(authority.substr(1, close - 1));
    const std::string_view rest = authority.substr(close + 1);
    if (!rest.empty()) {
      if (!rest.starts_with(':')) return false;
      port = rest.substr(1);
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    parsed.host = std::string(authority.substr(0, colon));
    if (colon != std::string_view::npos) port = authority.substr(colon + 1);
  }
  if (parsed.host.empty()) return false;
  if (port.empty()) {
    parsed.port = parsed.tls ? "443" : "80";
  } else {
    if (port.size() > 5 || !std::ranges::all_of(port, [](char c) {
          return c >= '0' && c <= '9';
        })) {
      return false;
    }
    parsed.port = std::string(port);
  }
  *out = std::move(parsed);
  return true;
}

std::string_view HttpClientResponse::Header(std::string_view name) const {
  for (const auto& [key, value] : headers) {
    if (key == name) return value;
  }
  return {};
}

void SetHttpClientCaFile(std::string path) {
  const std::scoped_lock lock(CaMutex());
  CaFile() = std::move(path);
}

bool HttpFetch(const HttpClientRequest& request, HttpClientResponse* response,
               std::string* error) {
  std::string url = request.url;
  const auto deadline = std::chrono::steady_clock::now() + request.timeout;
  for (int redirect = 0;; ++redirect) {
    ParsedUrl parsed;
    if (!ParseUrl(url, &parsed)) {
      *error = std::format("bad URL: {}", url);
      return false;
    }
    asio::ssl::context tls(asio::ssl::context::tls_client);
    if (parsed.tls) {
      const std::string ca = FindCaFile();
      std::error_code ca_error;
      if (!ca.empty()) tls.load_verify_file(ca, ca_error);
      if (ca.empty() || ca_error) {
        *error = ca.empty()
                     ? std::string("no CA bundle found")
                     : std::format("CA bundle {}: {}", ca, ca_error.message());
        return false;
      }
      tls.set_verify_mode(asio::ssl::verify_peer);
    }
    std::string host_header = parsed.host.find(':') != std::string::npos
                                  ? "[" + parsed.host + "]"
                                  : parsed.host;
    if (parsed.port != (parsed.tls ? "443" : "80")) {
      host_header += ":" + parsed.port;
    }
    std::string wire = std::format(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: LarpGuard/{}\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n",
        request.method, parsed.target, host_header, kVersion);
    for (const auto& [name, value] : request.headers) {
      wire += std::format("{}: {}\r\n", name, value);
    }
    if (!request.body.empty() || request.method == "POST") {
      wire += std::format("Content-Length: {}\r\n", request.body.size());
    }
    wire += "\r\n";
    wire += request.body;

    ResponseParser parser(request.max_body);
    std::string fetch_error;
    asio::io_context io;
    bool finished = false;
    asio::co_spawn(io, FetchOnce(&tls, parsed, wire, &parser, &fetch_error),
                   [&finished, &fetch_error](const std::exception_ptr& e) {
                     finished = true;
                     if (e && fetch_error.empty()) fetch_error = "failed";
                   });
    // In slices, so a stop request (shutdown) cuts the wait short.
    while (!finished && !request.stop.stop_requested()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) break;
      io.run_for(std::min<std::chrono::steady_clock::duration>(
          deadline - now, std::chrono::milliseconds(100)));
    }
    if (!finished) {
      *error = std::format(
          "{}: {}", url,
          request.stop.stop_requested() ? "cancelled" : "timed out");
      return false;
    }
    if (!fetch_error.empty()) {
      *error = std::format("{}: {}", url, fetch_error);
      return false;
    }
    const int status = parser.parser.status_code;
    std::string location;
    for (const auto& [name, value] : parser.headers) {
      if (Lower(name) == "location") location = value;
    }
    if ((status == 301 || status == 302 || status == 303 || status == 307 ||
         status == 308) &&
        !location.empty() && request.method == "GET" &&
        redirect < request.max_redirects) {
      url = Resolve(parsed, location);
      continue;
    }
    HttpClientResponse out;
    out.status = status;
    for (auto& [name, value] : parser.headers) {
      out.headers.emplace_back(Lower(name), std::move(value));
    }
    out.body = std::move(parser.body);
    *response = std::move(out);
    return true;
  }
}

}  // namespace bot_shield
