#ifndef BOT_SHIELD_RATELIMIT_LIMITS_H_
#define BOT_SHIELD_RATELIMIT_LIMITS_H_

#include <asio/ip/address.hpp>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"
#include "ratelimit/gcra.h"
#include "ratelimit/store.h"

namespace bot_shield {

// A request rate limit as written in the configuration.
struct RateLimitSpec {
  std::string name;
  // Filters; an empty list matches everything.
  std::vector<std::string> hosts;    // Exact or "*.parent".
  std::vector<std::string> paths;    // Globs on the path without query.
  std::vector<std::string> methods;  // Uppercase.
  std::vector<std::string> classes;  // human, suspicious, bot.
  // Key components: ip, ip_prefix, ja4, fp, host, header:<name>,
  // cookie:<name>. A request missing a component is not limited by it.
  std::vector<std::string> key;
  int64_t count = 0;
  std::chrono::milliseconds period{0};
  int64_t burst = 1;
};

// Parses "120/m": count per second (s), minute (m), hour (h) or day (d).
bool ParseRate(std::string_view text, int64_t* count,
               std::chrono::milliseconds* period);

// What the limits look at for one request.
struct RateLimitRequest {
  const HttpRequest* request = nullptr;
  asio::ip::address ip;
  std::string_view host;
  std::string_view path;
  std::string_view method;
  std::string_view bot_class;
  std::string_view ja4;
  std::string_view h2_fingerprint;
};

struct RateLimitHit {
  std::string name;
  GcraResult result;
  int64_t burst = 0;
  int64_t window_seconds = 0;
};

// Compiled request limits. Every matching limit counts the request; the
// first one that refuses it is reported.
class RateLimitSet {
 public:
  static bool Compile(const std::vector<RateLimitSpec>& specs,
                      RateLimitSet* limits, std::string* error);

  bool empty() const { return limits_.empty(); }

  std::optional<RateLimitHit> Check(const RateLimitRequest& request,
                                    RateLimitStore* store,
                                    int64_t now_ns) const;

 private:
  struct Limit {
    RateLimitSpec spec;
    GcraParams params;
  };

  static bool Matches(const Limit& limit, const RateLimitRequest& request);
  // Empty when a key component is missing.
  static std::string BuildKey(const Limit& limit,
                              const RateLimitRequest& request);

  std::vector<Limit> limits_;
};

// Header value of a "Retry-After" for `nanoseconds` (whole seconds, >= 1).
int64_t RetryAfterSeconds(int64_t nanoseconds);

}  // namespace bot_shield

#endif  // BOT_SHIELD_RATELIMIT_LIMITS_H_
