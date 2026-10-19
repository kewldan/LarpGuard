#ifndef BOT_SHIELD_CHALLENGE_CAPTCHA_H_
#define BOT_SHIELD_CHALLENGE_CAPTCHA_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "challenge/challenger.h"
#include "challenge/token.h"

namespace bot_shield {

enum class CaptchaProvider {
  kNone,
  kBuiltin,
  kTurnstile,
  kHcaptcha,
  kRecaptcha
};

bool ParseCaptchaProvider(std::string_view text, CaptchaProvider* provider);
std::string_view CaptchaProviderName(CaptchaProvider provider);

struct CaptchaSettings {
  CaptchaProvider provider = CaptchaProvider::kNone;
  // Third-party providers.
  std::string site_key;
  std::string secret;
  std::string verify_url;  // "" = the provider's siteverify.
  bool check_hostname = true;
  std::chrono::seconds provider_timeout{10};
  int threads = 2;
  std::size_t max_queue = 256;
  // Built-in puzzle: rounds in a row, each answered within
  // [min_answer, round_timeout] of being shown (server time).
  int rounds = 2;
  std::chrono::milliseconds min_answer{800};
  std::chrono::seconds round_timeout{30};
  // Proof of work on the CAPTCHA page (leading zero bits).
  int difficulty = 12;
  std::chrono::seconds page_max_age{600};
  // Tests only: puzzles from seeds test_seed, test_seed + 1, ... instead of
  // random ones, so a test can compute the answers.
  uint64_t test_seed = 0;
};

// The CAPTCHA (docs/architecture.md 7.1): an escalation above the JS
// challenge. Solving it sets a level-captcha clearance token, which action
// "captcha" requires.
//
// Built-in puzzle: "click the shape that matches the sample", rendered on
// the server, in `rounds` rounds. Against solving farms the answer is bound
// to the browser that ran the probes (TLS fingerprint and network), each
// round must come back within seconds of being shown, a nonce works once,
// and the pointer must have moved like a hand to the click.
// Third-party widgets (Turnstile, hCaptcha, reCAPTCHA) are verified with the
// provider's siteverify on background threads, bound to the page by cdata
// (Turnstile), hostname and a one-time nonce.
class Captcha {
 public:
  Captcha(CaptchaSettings settings, const Challenger* challenger);
  ~Captcha();
  Captcha(const Captcha&) = delete;
  Captcha& operator=(const Captcha&) = delete;

  CaptchaProvider provider() const { return settings_.provider; }

  // The CAPTCHA page for a client.
  std::string Page(const ClientBinding& binding, std::string_view return_path,
                   int64_t now_ms) const;

  // Built-in puzzle: GET /__bs/captcha/answer. JSON body for the page and,
  // when solved, the clearance cookie.
  struct Answer {
    std::string body;        // JSON.
    std::string set_cookie;  // Solved: the level-captcha token.
    // passed, failed:<why>, next (another round), retry (new puzzle).
    std::string outcome;
    std::string client_fp;
  };
  Answer AnswerPuzzle(std::string_view query, const ClientBinding& binding,
                      std::string_view user_agent, int64_t now_ms);

  // Third-party: GET /__bs/captcha/verify. Checks what can be checked here
  // and, when the provider has to decide, queues its siteverify; `done`
  // runs later on a pool thread (post it back to the connection's loop).
  struct Verdict {
    bool passed = false;
    std::string reason;  // passed or failed:<why>.
    std::string return_path = "/";
    std::string set_cookie;
    std::string client_fp;
  };
  // Returns false (with `immediate` filled) when it decided without the
  // provider; true when `done` will be called.
  bool VerifyWidget(std::string_view query, const ClientBinding& binding,
                    std::string_view user_agent, std::string_view host,
                    std::string_view remote_ip, int64_t now_ms,
                    Verdict* immediate, std::function<void(Verdict)> done);

  // Blocks until no siteverify is queued or running (tests).
  void WaitIdle();

 private:
  struct Job {
    std::string token;
    std::string remote_ip;
    std::string host;
    std::string cdata;
    Verdict verdict;  // Filled except passed/reason/set_cookie.
    ClientBinding binding;
    int64_t now = 0;
    std::function<void(Verdict)> done;
  };

  void Run(const std::stop_token& stop);
  Verdict Siteverify(const Job& job) const;
  // A nonce or provider token seen before (replays); records it.
  bool Used(const std::string& key, int64_t now_ms);
  std::string NewRound(const ClientBinding& binding,
                       std::string_view return_path, int round, int64_t now_ms,
                       std::string* image, std::string* sample) const;

  CaptchaSettings settings_;
  const Challenger* challenger_;
  std::mutex mutex_;
  std::condition_variable_any wake_;
  std::condition_variable_any idle_;
  std::deque<Job> queue_;
  int running_ = 0;
  std::map<std::string, int64_t, std::less<>> used_;  // key -> expiry ms.
  mutable std::atomic<uint64_t> next_test_seed_{0};
  std::vector<std::jthread> threads_;  // Last: joined first.
};

// What a provider's siteverify said (Turnstile, hCaptcha and reCAPTCHA share
// the layout): success, hostname, challenge_ts, cdata (Turnstile).
struct SiteverifyResult {
  bool success = false;
  std::string hostname;
  std::string cdata;
  int64_t challenge_ts = 0;  // Unix seconds; 0 = absent.
  std::string error;
};
SiteverifyResult ParseSiteverify(std::string_view json);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CHALLENGE_CAPTCHA_H_
