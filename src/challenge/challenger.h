#ifndef BOT_SHIELD_CHALLENGE_CHALLENGER_H_
#define BOT_SHIELD_CHALLENGE_CHALLENGER_H_

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

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

  // HTML page that solves the challenge and comes back via /__bs/verify.
  std::string Page(const ClientBinding& binding, int difficulty,
                   std::string_view return_path, int64_t now) const;

  struct Result {
    bool passed = false;
    // Why it failed: bad_nonce, binding, pow, webdriver, headless, ...
    std::string reason;
    std::string return_path = "/";
    // Set-Cookie value on success.
    std::string set_cookie;
  };
  // Checks a /__bs/verify query (n: nonce, c: counter, s: signals).
  Result Verify(std::string_view query, const ClientBinding& binding,
                int64_t now) const;

  // A valid, unexpired __bs token bound to this client.
  bool HasValidToken(const HttpRequest& request, const ClientBinding& binding,
                     int64_t now) const;

  // The Cookie header without the gateway's own cookie ("" if nothing left).
  static std::string StripCookie(std::string_view cookie_header);

 private:
  ChallengeSettings settings_;
};

// A request a browser makes to show a page (where a challenge page can be
// shown instead).
bool IsNavigation(const HttpRequest& request);

// Body for a failed or non-HTML challenge.
std::string ChallengeFailedPage();

}  // namespace bot_shield

#endif  // BOT_SHIELD_CHALLENGE_CHALLENGER_H_
