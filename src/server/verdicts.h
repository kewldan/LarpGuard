#ifndef BOT_SHIELD_SERVER_VERDICTS_H_
#define BOT_SHIELD_SERVER_VERDICTS_H_

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "config/config.h"
#include "fp/library.h"
#include "model/gbdt.h"
#include "ratelimit/limits.h"
#include "score/policy.h"
#include "score/rules.h"
#include "score/scorer.h"

namespace bot_shield {

// Everything that decides verdicts and can change without a restart
// (SIGHUP, POST /reload): fingerprint library, scoring thresholds, policy
// and host modes, rules, rate limits, throttle, honeypot paths, the AI
// crawler action and the model. Immutable once built; a request takes one
// snapshot and uses it to the end.
struct VerdictSet {
  // Builds from `config`; the library and the model are read from their
  // files (or built in). Nothing is published on error.
  static bool Build(const Config& config,
                    std::shared_ptr<const VerdictSet>* out, std::string* error);

  std::shared_ptr<const FingerprintLibrary> library;
  std::shared_ptr<const Scorer> scorer;  // Points into `library`.
  std::shared_ptr<const Policy> policy;
  RuleSet rules;
  RateLimitSet rate_limits;
  // Action "throttle": one limit, named "throttle".
  RateLimitSet throttle;
  std::vector<std::string> honeypot_paths;
  std::optional<Action> ai_crawler_action;
  // Web Bot Auth agents (hosts or "*.parent") trusted as verified bots.
  std::vector<std::string> trusted_agents;
  std::shared_ptr<const GbdtModel> model;  // Null without a model file.
  double model_threshold = 0.8;
  // For logs and /status.
  std::size_t generation = 0;
};

class VerdictStore {
 public:
  std::shared_ptr<const VerdictSet> snapshot() const;
  // Publishes `verdicts` with the next generation number.
  void set(const std::shared_ptr<const VerdictSet>& verdicts);

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<const VerdictSet> current_;
  std::size_t generation_ = 0;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_VERDICTS_H_
