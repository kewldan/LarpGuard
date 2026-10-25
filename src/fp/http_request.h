#ifndef BOT_SHIELD_FP_HTTP_REQUEST_H_
#define BOT_SHIELD_FP_HTTP_REQUEST_H_

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield {

// A request as seen by a passive tap on the client-to-upstream stream.
struct HttpRequest {
  // First value of a header by lowercase name, or "" if absent.
  std::string_view Header(std::string_view lowercase_name) const;
  bool HasHeader(std::string_view lowercase_name) const;

  // "1.0", "1.1" or "2".
  std::string version;
  std::string method;
  // Host header or :authority.
  std::string authority;
  // Request target (path and query) or :path.
  std::string target;
  // Header names in wire order, without pseudo-headers. Original case on
  // HTTP/1.x (case is part of the fingerprint), lowercase on HTTP/2.
  std::vector<std::string> header_names;
  // HTTP/2 only: pseudo-headers in wire order (":method", ":authority", ...).
  std::vector<std::string> pseudo_header_order;
  // All headers with lowercase names, in wire order.
  std::vector<std::pair<std::string, std::string>> headers;
};

// Value of a cookie from the Cookie header(s); nullopt when absent (an
// empty value is present).
std::optional<std::string_view> FindCookie(const HttpRequest& request,
                                           std::string_view name);

// Value of a query parameter in `query` (after '?', as sent: not
// percent-decoded); nullopt when absent. "?a" has "a" with "".
std::optional<std::string_view> FindQueryParam(std::string_view query,
                                               std::string_view name);

using HttpRequestCallback = std::function<void(HttpRequest&&)>;

// Limits that keep a tap cheap; a tap that exceeds them stops observing.
inline constexpr std::size_t kMaxTapHeaderBytes = std::size_t{64} * 1024;
inline constexpr int kMaxTapRequests = 128;

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_HTTP_REQUEST_H_
