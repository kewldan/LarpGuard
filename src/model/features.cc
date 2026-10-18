#include "model/features.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <string>
#include <string_view>
#include <system_error>

#include "behavior/behavior.h"
#include "fp/http_request.h"
#include "fp/user_agent.h"

namespace bot_shield {
namespace {

// Two decimal digits of a JA4 count ("15" in "t13d1516h2"), 0 if missing.
float Ja4Count(std::string_view ja4, std::size_t at) {
  if (ja4.size() < at + 2) return 0;
  int value = 0;
  const auto [ptr, ec] =
      std::from_chars(ja4.data() + at, ja4.data() + at + 2, value);
  return ec == std::errc() && ptr == ja4.data() + at + 2
             ? static_cast<float>(value)
             : 0;
}

float Flag(bool value) { return value ? 1.0F : 0.0F; }

}  // namespace

std::array<float, kFeatureCount> ExtractFeatures(const FeatureInput& input) {
  std::array<float, kFeatureCount> out{};
  const HttpRequest& request = *input.request;
  const std::string_view user_agent = request.Header("user-agent");
  const UserAgent ua = ParseUserAgent(user_agent);
  const std::size_t question = input.path.find('?');
  const std::string_view path = input.path.substr(0, question);
  const RequestFacts facts = ClassifyRequest(
      request.method, path, request.Header("sec-fetch-mode"),
      request.Header("sec-fetch-dest"), request.Header("accept"),
      request.Header("x-requested-with"));
  const auto has_signal = [&](std::string_view name) {
    return std::ranges::find(input.reasons, name) != input.reasons.end();
  };
  const std::string_view ja4 = input.ja4;

  std::size_t i = 0;
  out[i++] = Flag(input.http2);
  out[i++] = Flag(input.offered_h2);
  out[i++] = static_cast<float>(request.headers.size());
  out[i++] = Flag(request.HasHeader("cookie"));
  out[i++] = Flag(request.HasHeader("referer"));
  out[i++] = Flag(request.HasHeader("accept-language"));
  out[i++] = Flag(request.HasHeader("accept-encoding"));
  out[i++] = Flag(request.HasHeader("sec-ch-ua"));
  out[i++] = Flag(request.HasHeader("sec-fetch-mode"));
  out[i++] = static_cast<float>(user_agent.size()) / 100.0F;
  out[i++] = Flag(request.method == "GET" || request.method == "HEAD");
  out[i++] = Flag(question != std::string_view::npos);
  out[i++] = Flag(ua.engine == "chromium");
  out[i++] = Flag(ua.engine == "firefox");
  out[i++] = Flag(ua.engine == "webkit");
  out[i++] = Flag(ua.engine.empty());
  out[i++] = Flag(ua.mobile);
  // JA4 part a: t13d1516h2 = protocol, version, SNI, ciphers, extensions,
  // first ALPN.
  out[i++] = Flag(ja4.size() >= 3 && ja4.substr(1, 2) == "13");
  out[i++] = Ja4Count(ja4, 4);
  out[i++] = Ja4Count(ja4, 6);
  out[i++] = Flag(ja4.size() >= 10 && ja4.substr(8, 2) == "h2");
  out[i++] = Flag(ja4.size() >= 4 && ja4[3] == 'd');
  out[i++] = Flag(input.tcp_initial_ttl == 64);
  out[i++] = Flag(input.tcp_initial_ttl == 128);
  out[i++] = Flag(input.tcp_initial_ttl == 0);
  out[i++] = Flag(facts.navigation);
  out[i++] = Flag(facts.api);
  out[i++] = Flag(facts.asset);
  for (std::size_t s = i; s < kFeatureCount; ++s) {
    out[s] = Flag(has_signal(kFeatureNames[s].substr(4)));  // "sig_".
  }
  return out;
}

}  // namespace bot_shield
