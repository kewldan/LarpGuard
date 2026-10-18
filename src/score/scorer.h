#ifndef BOT_SHIELD_SCORE_SCORER_H_
#define BOT_SHIELD_SCORE_SCORER_H_

#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"
#include "fp/library.h"

namespace bot_shield {

// What is known about one request for scoring.
struct ScoringInput {
  const HttpRequest* request = nullptr;
  std::string_view ja4;             // Empty without TLS.
  bool offered_h2 = false;          // The ClientHello offered ALPN "h2".
  std::string_view h2_fingerprint;  // Empty on HTTP/1.x.
  std::string_view pseudo_order;    // "m,a,s,p"; empty on HTTP/1.x.
  std::string_view header_fp;       // Own header-order fingerprint.
  int tcp_initial_ttl = 0;          // 0: unknown (no SYN capture).
};

// kVerifiedBot: a search crawler whose address was verified (never from a
// score; see crawler/verifier.h).
enum class BotClass { kHuman, kSuspicious, kBot, kVerifiedBot };

std::string_view BotClassName(BotClass bot_class);

struct Verdict {
  int score = 0;  // 0..100.
  BotClass bot_class = BotClass::kHuman;
  // Signal names, e.g. "ua_tls_mismatch", "known_automation:<id>".
  std::vector<std::string> reasons;
};

// Weighted consistency checks between what the client claims (User-Agent,
// client hints) and what its network stack shows (JA4, HTTP/2, TCP).
class Scorer {
 public:
  Scorer(const FingerprintLibrary* library, int suspicious_threshold,
         int bot_threshold);

  Verdict Score(const ScoringInput& input) const;
  // Class for a score (after rules adjusted it).
  BotClass Classify(int score) const;
  // Weight of a signal in the library (0 if unknown).
  int SignalWeight(std::string_view signal) const {
    return library_->Weight(signal);
  }

 private:
  const FingerprintLibrary* library_;
  int suspicious_threshold_;
  int bot_threshold_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SCORE_SCORER_H_
