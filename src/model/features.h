#ifndef BOT_SHIELD_MODEL_FEATURES_H_
#define BOT_SHIELD_MODEL_FEATURES_H_

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"

namespace bot_shield {

// Feature set of the model signal (docs/architecture.md, 6.1). The gateway
// computes the vector for every scored request and logs it in the req event,
// so training (tools/train_model.py) reads exactly these values. Changing
// the list means a new kFeatureSetVersion and a retrained model.
inline constexpr std::string_view kFeatureSetVersion = "f1";

inline constexpr std::array<std::string_view, 40> kFeatureNames = {
    // Protocol and headers.
    "http2", "offered_h2", "header_count", "has_cookie", "has_referer",
    "has_accept_language", "has_accept_encoding", "has_sec_ch_ua",
    "has_sec_fetch", "ua_length", "method_get", "has_query",
    // What the User-Agent claims (not tools or crawlers: those are labels).
    "engine_chromium", "engine_firefox", "engine_webkit", "engine_none",
    "ua_mobile",
    // TLS (JA4 part a) and TCP.
    "tls13", "tls_ciphers", "tls_extensions", "alpn_h2", "tls_sni", "ttl_64",
    "ttl_128", "ttl_unknown",
    // Request kind.
    "navigation", "api", "asset",
    // Signals that are not used as training labels.
    "sig_ua_tls_mismatch", "sig_ua_h2_mismatch", "sig_browser_without_h2",
    "sig_missing_client_hints", "sig_missing_fetch_metadata",
    "sig_missing_accept_language", "sig_os_tcp_mismatch",
    "sig_behavior_regular_timing", "sig_behavior_not_found",
    "sig_behavior_api_without_page", "sig_behavior_no_assets",
    "sig_behavior_sequential_ids"};

inline constexpr std::size_t kFeatureCount = kFeatureNames.size();

struct FeatureInput {
  const HttpRequest* request = nullptr;
  std::string_view path;  // Request target (path and query).
  std::string_view ja4;
  bool http2 = false;
  bool offered_h2 = false;
  int tcp_initial_ttl = 0;
  // Verdict reasons so far (signals).
  std::span<const std::string> reasons;
};

std::array<float, kFeatureCount> ExtractFeatures(const FeatureInput& input);

}  // namespace bot_shield

#endif  // BOT_SHIELD_MODEL_FEATURES_H_
