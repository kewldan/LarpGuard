#ifndef BOT_SHIELD_SERVER_WHOAMI_H_
#define BOT_SHIELD_SERVER_WHOAMI_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fp/library.h"

namespace bot_shield {

inline constexpr std::string_view kWhoamiPath = "/__bs/whoami";

// GET /__bs/whoami (config `whoami: true`): what the gateway sees and
// decides about the very request that asks, instead of acting on it. For
// trying clients against the scoring; it shows the reasons and weights, so
// it is off by default.
struct WhoamiReport {
  std::string request_id;
  std::string host;
  // Host mode: "shadow", "enforce" or "off" (no verdict at all).
  std::string mode;

  // The client's own address (it is theirs to see) and network.
  std::string ip;
  std::string ip_prefix;
  uint32_t asn = 0;
  std::string asn_org;
  bool hosting = false;

  // What the client says it is (User-Agent).
  std::string user_agent;
  std::string claimed_family;  // "chrome", "firefox", ... or "".
  int claimed_major = 0;
  std::string claimed_os;
  std::string claimed_tool;  // "curl", "python-requests", ... or "".
  bool claims_crawler = false;
  bool headless = false;

  // What the network stack shows.
  std::string http_version;  // "1.1", "2", "3".
  bool offered_h2 = false;
  std::string ja4;
  std::string h2_fingerprint;
  std::string pseudo_order;
  std::string header_fp;
  int tcp_initial_ttl = 0;  // 0: not captured.
  // Browser engines whose TLS cipher list matches the JA4 ("chromium").
  std::vector<std::string> tls_engines;

  // The verdict and what follows from it.
  int score = 0;
  std::string bot_class;
  // Reasons with the weight each added (0 when it only records).
  std::vector<std::pair<std::string, int>> reasons;
  bool token_valid = false;
  // On this host now, and with the host in enforce mode.
  std::string action;
  std::string would_action;
};

// Browser engines ("chromium", "firefox", "webkit") whose profile lists
// the JA4's cipher hash.
std::vector<std::string> MatchingTlsEngines(const FingerprintLibrary& library,
                                            std::string_view ja4);

// One line on who the client looks like, e.g. "a real browser (Chrome
// 141)", "curl, an HTTP tool".
std::string WhoamiHeadline(const WhoamiReport& report);

// Plain text for curl and the like.
std::string RenderWhoamiText(const WhoamiReport& report);
std::string RenderWhoamiJson(const WhoamiReport& report);
// A self-contained page (inline style, no script).
std::string RenderWhoamiHtml(const WhoamiReport& report);

enum class WhoamiFormat { kText, kJson, kHtml };

// ?format=json|text|html wins; then Accept: JSON, then HTML (browsers),
// otherwise text.
WhoamiFormat ChooseWhoamiFormat(std::string_view query,
                                std::string_view accept);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_WHOAMI_H_
