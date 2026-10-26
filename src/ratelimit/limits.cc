#include "ratelimit/limits.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/host.h"
#include "events/events.h"
#include "fp/http_request.h"
#include "fp/library.h"
#include "ratelimit/gcra.h"
#include "ratelimit/store.h"
#include "ratelimit/valkey.h"

namespace bot_shield {
namespace {

constexpr char kSeparator = '\x1f';

bool IsKnownComponent(std::string_view component) {
  return component == "ip" || component == "ip_prefix" || component == "ja4" ||
         component == "fp" || component == "host" || component == "session" ||
         component == "asn" ||
         (component.starts_with("header:") && component.size() > 7) ||
         (component.starts_with("cookie:") && component.size() > 7);
}

}  // namespace

std::string_view RateLimitModeName(RateLimitMode mode) {
  switch (mode) {
    case RateLimitMode::kLocal:
      return "local";
    case RateLimitMode::kSynced:
      return "synced";
    case RateLimitMode::kStrict:
      return "strict";
  }
  return "local";
}

bool ParseRateLimitMode(std::string_view text, RateLimitMode* mode) {
  if (text == "local") {
    *mode = RateLimitMode::kLocal;
  } else if (text == "synced") {
    *mode = RateLimitMode::kSynced;
  } else if (text == "strict") {
    *mode = RateLimitMode::kStrict;
  } else {
    return false;
  }
  return true;
}

bool ParseRate(std::string_view text, int64_t* count,
               std::chrono::milliseconds* period) {
  const std::size_t slash = text.find('/');
  if (slash == std::string_view::npos || slash + 2 != text.size()) {
    return false;
  }
  const std::string_view number = text.substr(0, slash);
  const auto [ptr, ec] =
      std::from_chars(number.data(), number.data() + number.size(), *count);
  if (ec != std::errc() || ptr != number.data() + number.size() ||
      *count <= 0) {
    return false;
  }
  switch (text.back()) {
    case 's':
      *period = std::chrono::seconds(1);
      return true;
    case 'm':
      *period = std::chrono::minutes(1);
      return true;
    case 'h':
      *period = std::chrono::hours(1);
      return true;
    case 'd':
      *period = std::chrono::hours(24);
      return true;
    default:
      return false;
  }
}

int64_t RetryAfterSeconds(int64_t nanoseconds) {
  constexpr int64_t kSecond = 1'000'000'000;
  return std::max<int64_t>(1, (nanoseconds + kSecond - 1) / kSecond);
}

bool RateLimitSet::Compile(const std::vector<RateLimitSpec>& specs,
                           RateLimitSet* limits, std::string* error) {
  RateLimitSet out;
  std::set<std::string> names;
  for (const RateLimitSpec& spec : specs) {
    const auto fail = [&](std::string_view message) {
      *error = std::format("rate limit '{}': {}", spec.name, message);
      return false;
    };
    if (spec.name.empty() || !names.insert(spec.name).second) {
      return fail("names must be unique and non-empty");
    }
    if (spec.count <= 0 || spec.period.count() <= 0) {
      return fail("rate must be like 120/m");
    }
    if (spec.burst < 1) return fail("burst must be at least 1");
    if (spec.key.empty()) return fail("key needs at least one component");
    for (const int status : spec.statuses) {
      if (status < 100 || status > 599) {
        return fail(std::format("status {} is not an HTTP status", status));
      }
    }
    for (const std::string& component : spec.key) {
      if (!IsKnownComponent(component)) {
        return fail(std::format("unknown key component '{}'", component));
      }
    }
    for (const std::string& bot_class : spec.classes) {
      if (bot_class != "human" && bot_class != "suspicious" &&
          bot_class != "bot" && bot_class != "verified_bot") {
        return fail(std::format("unknown class '{}'", bot_class));
      }
    }
    Limit limit;
    limit.spec = spec;
    for (std::string& host : limit.spec.hosts) host = NormalizeHost(host);
    for (std::string& method : limit.spec.methods) {
      std::ranges::transform(method, method.begin(), [](char c) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      });
    }
    for (std::string& component : limit.spec.key) {
      // Header names compare lowercase.
      if (component.starts_with("header:")) {
        std::ranges::transform(component, component.begin(), [](char c) {
          return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });
      }
    }
    limit.params = GcraParams::FromRate(
        spec.count,
        std::chrono::duration_cast<std::chrono::nanoseconds>(spec.period)
            .count(),
        spec.burst);
    out.limits_.push_back(std::move(limit));
  }
  *limits = std::move(out);
  return true;
}

bool RateLimitSet::Matches(const Limit& limit,
                           const RateLimitRequest& request) {
  const RateLimitSpec& spec = limit.spec;
  const auto any = [](const std::vector<std::string>& list, auto predicate) {
    return list.empty() || std::ranges::any_of(list, predicate);
  };
  return any(spec.hosts,
             [&](const std::string& host) {
               return HostMatches(host, request.host);
             }) &&
         any(spec.paths,
             [&](const std::string& path) {
               return GlobMatch(path, request.path);
             }) &&
         any(spec.methods,
             [&](const std::string& method) {
               return method == request.method;
             }) &&
         any(spec.classes, [&](const std::string& bot_class) {
           return bot_class == request.bot_class;
         });
}

std::string RateLimitSet::BuildKey(const Limit& limit,
                                   const RateLimitRequest& request) {
  std::string key = limit.spec.name;
  for (const std::string& component : limit.spec.key) {
    std::string value;
    if (component == "ip") {
      const asio::ip::address& ip = request.ip;
      value = ip.is_v6() && ip.to_v6().is_v4_mapped()
                  ? asio::ip::make_address_v4(asio::ip::v4_mapped, ip.to_v6())
                        .to_string()
                  : ip.to_string();
    } else if (component == "ip_prefix") {
      value = IpPrefix(request.ip);
    } else if (component == "ja4") {
      value = request.ja4;
    } else if (component == "fp") {
      if (!request.ja4.empty()) {
        value = std::format("{}|{}", request.ja4, request.h2_fingerprint);
      }
    } else if (component == "host") {
      value = request.host;
    } else if (component == "session") {
      value = request.session;
    } else if (component == "asn") {
      if (request.asn != 0) value = std::to_string(request.asn);
    } else if (component.starts_with("header:")) {
      value = request.request->Header(std::string_view(component).substr(7));
    } else if (component.starts_with("cookie:")) {
      value =
          FindCookie(*request.request, std::string_view(component).substr(7))
              .value_or(std::string_view());
    }
    if (value.empty()) return {};
    key.push_back(kSeparator);
    key += value;
  }
  return key;
}

std::vector<std::string> RateLimitSet::NamesForHost(
    std::string_view host) const {
  std::vector<std::string> names;
  for (const Limit& limit : limits_) {
    if (limit.spec.hosts.empty() ||
        std::ranges::any_of(limit.spec.hosts, [&](const std::string& pattern) {
          return HostMatches(pattern, host);
        })) {
      names.push_back(limit.spec.name);
    }
  }
  return names;
}

std::optional<RateLimitHit> RateLimitSet::Check(
    const RateLimitRequest& request, RateLimitStore* store, int64_t now_ns,
    std::vector<ResponseCount>* on_response, ValkeyLimiter* valkey,
    std::vector<StrictCheck>* strict) const {
  std::optional<RateLimitHit> hit;
  for (const Limit& limit : limits_) {
    if (!Matches(limit, request)) continue;
    std::string key = BuildKey(limit, request);
    if (key.empty()) continue;
    const bool by_response = !limit.spec.statuses.empty();
    const int64_t window =
        std::chrono::duration_cast<std::chrono::seconds>(limit.spec.period)
            .count();
    if (limit.spec.mode == RateLimitMode::kStrict && !by_response &&
        valkey != nullptr && strict != nullptr && valkey->available()) {
      strict->push_back(StrictCheck{limit.spec.name, std::move(key),
                                    limit.params, limit.spec.burst, window});
      continue;
    }
    const GcraResult result = by_response
                                  ? store->Peek(key, limit.params, now_ns)
                                  : store->Check(key, limit.params, now_ns);
    if (!by_response && result.allowed && valkey != nullptr &&
        limit.spec.mode == RateLimitMode::kSynced) {
      valkey->NoteSynced(key, limit.params);
    }
    if (by_response && result.allowed && on_response != nullptr) {
      on_response->push_back(
          ResponseCount{std::move(key), limit.params, limit.spec.statuses});
    }
    if (!result.allowed && !hit) {
      hit = RateLimitHit{limit.spec.name, result, limit.spec.burst, window};
    }
  }
  return hit;
}

void CountResponse(const std::vector<ResponseCount>& counts, int status,
                   RateLimitStore* store, int64_t now_ns) {
  for (const ResponseCount& count : counts) {
    if (std::ranges::find(count.statuses, status) != count.statuses.end()) {
      store->Check(count.key, count.params, now_ns);
    }
  }
}

}  // namespace bot_shield
