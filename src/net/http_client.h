#ifndef BOT_SHIELD_NET_HTTP_CLIENT_H_
#define BOT_SHIELD_NET_HTTP_CLIENT_H_

#include <chrono>
#include <cstddef>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield {

// "https://host[:port]/path?query" split into parts.
struct ParsedUrl {
  bool tls = true;
  std::string host;
  std::string port;
  std::string target = "/";  // Path and query.
};

bool ParseUrl(std::string_view url, ParsedUrl* out);

struct HttpClientRequest {
  std::string method = "GET";
  std::string url;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  std::chrono::milliseconds timeout{20000};
  std::size_t max_body = std::size_t{64} << 20;
  int max_redirects = 3;
  // Aborts the request (shutdown of the thread that made it).
  std::stop_token stop;
};

struct HttpClientResponse {
  int status = 0;
  // Lowercase names.
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;

  std::string_view Header(std::string_view name) const;
};

// Blocking HTTP/1.1 client for background work (downloads, CAPTCHA and key
// lookups): never call it on a worker's event loop. HTTPS verifies the
// server against the system CA bundle (or `ca_file`, see
// SetHttpClientCaFile). Follows redirects for GET.
bool HttpFetch(const HttpClientRequest& request, HttpClientResponse* response,
               std::string* error);

// CA bundle for HTTPS; "" = first of the usual system locations.
void SetHttpClientCaFile(std::string path);

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_HTTP_CLIENT_H_
