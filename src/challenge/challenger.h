#ifndef BOT_SHIELD_CHALLENGE_CHALLENGER_H_
#define BOT_SHIELD_CHALLENGE_CHALLENGER_H_

#include <chrono>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "challenge/token.h"
#include "fp/http_request.h"
#include "score/scorer.h"

namespace bot_shield {

struct ChallengeSettings {
  TokenKeys keys;
  std::chrono::seconds token_ttl{std::chrono::hours(12)};
  // Leading zero bits of the proof of work, by class.
  int suspicious_difficulty = 16;
  int bot_difficulty = 19;
  // Score taken off for a valid clearance token.
  int token_credit = 40;
  std::chrono::seconds nonce_max_age{300};
};

// What the challenge script found in the browser (docs/architecture.md
// 5.3), in three tiers:
//   fatal       automation that announces itself: always refused;
//   suspicious  likely automation or spoofing: CAPTCHA if one is set up,
//               otherwise refused;
//   soft        unusual but seen in real browsers: CAPTCHA if one is set
//               up, otherwise passed with the reasons recorded.
struct SignalCheck {
  std::string fatal;
  std::string suspicious;
  std::vector<std::string> soft;
  // 16 hex chars over canvas, WebGL, audio and fonts (events, clusters).
  std::string client_fp;
};

// `user_agent`: the request's header (the script reports a hash of the
// browser's own navigator.userAgent).
SignalCheck CheckSignals(const nlohmann::json& signals,
                         std::string_view user_agent);

// A valid clearance token of the request.
struct Clearance {
  std::string session;  // 16 hex chars of the token's hash.
  int level = kTokenLevelJs;
};

// The JS challenge (docs/architecture.md, section 7): a page that collects
// browser signals and solves a proof of work, the /__bs/verify endpoint and
// the __bs clearance cookie. Stateless: nonces and tokens carry an HMAC.
class Challenger {
 public:
  static constexpr std::string_view kPathPrefix = "/__bs/";
  static constexpr std::string_view kCookieName = "__bs";

  explicit Challenger(ChallengeSettings settings)
      : settings_(std::move(settings)) {}

  int DifficultyFor(BotClass bot_class) const;
  int token_credit() const { return settings_.token_credit; }
  const TokenKeys& keys() const { return settings_.keys; }
  // Secret for decoy watermarks (the active token key).
  std::string_view watermark_secret() const {
    return settings_.keys.Secret(settings_.keys.active_id());
  }

  // HTML page that solves the challenge and comes back via /__bs/verify.
  std::string Page(const ClientBinding& binding, int difficulty,
                   std::string_view return_path, int64_t now) const;

  struct Result {
    bool passed = false;
    // Why it failed: bad_nonce, binding, pow, webdriver, cdp, ...
    std::string reason;
    // Soft findings of a passed challenge.
    std::vector<std::string> soft;
    // A CAPTCHA should decide instead (suspicious failure or soft
    // findings); the caller shows one when it is configured.
    bool escalate = false;
    std::string return_path = "/";
    std::string client_fp;
    // Set-Cookie value on success.
    std::string set_cookie;
  };
  // Checks a /__bs/verify query (n: nonce, c: counter, s: signals).
  Result Verify(std::string_view query, const ClientBinding& binding,
                std::string_view user_agent, int64_t now) const;

  // Set-Cookie value of a clearance token at `level`.
  std::string ClearanceCookie(const ClientBinding& binding, int level,
                              int64_t now) const;

  std::optional<Clearance> FindClearance(const HttpRequest& request,
                                         const ClientBinding& binding,
                                         int64_t now) const;
  // A valid, unexpired __bs token bound to this client.
  bool HasValidToken(const HttpRequest& request, const ClientBinding& binding,
                     int64_t now) const {
    return FindClearance(request, binding, now).has_value();
  }
  // For a valid token: an id of the clearance session (rate limit key
  // "session"). nullopt without a valid token.
  std::optional<std::string> SessionId(const HttpRequest& request,
                                       const ClientBinding& binding,
                                       int64_t now) const {
    std::optional<Clearance> clearance = FindClearance(request, binding, now);
    if (!clearance) return std::nullopt;
    return std::move(clearance->session);
  }

  // The Cookie header without the gateway's own cookie ("" if nothing left).
  static std::string StripCookie(std::string_view cookie_header);

 private:
  ChallengeSettings settings_;
};

// A request a browser makes to show a page (where a challenge page can be
// shown instead).
bool IsNavigation(const HttpRequest& request);

// The gateway's own pages: a centred box with `body` (HTML).
std::string GatewayPage(std::string_view title, std::string_view body);

// Body for a failed or non-HTML challenge.
std::string ChallengeFailedPage();

}  // namespace bot_shield

#endif  // BOT_SHIELD_CHALLENGE_CHALLENGER_H_
