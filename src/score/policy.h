#ifndef BOT_SHIELD_SCORE_POLICY_H_
#define BOT_SHIELD_SCORE_POLICY_H_

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "score/scorer.h"

namespace bot_shield {

// What happens to a request. Challenge and throttle arrive with M3/M4.
enum class Action { kAllow, kBlock };

std::string_view ActionName(Action action);
bool ParseAction(std::string_view text, Action* action);

struct PolicySettings {
  // Shadow mode computes verdicts but never acts on them.
  bool enforce = false;
  int suspicious_threshold = 30;
  int bot_threshold = 70;
  Action suspicious_action = Action::kAllow;
  Action bot_action = Action::kBlock;
  int block_status = 403;
  // Per-host mode overrides: exact names or "*.parent" -> enforce?
  std::vector<std::pair<std::string, bool>> host_modes;
};

struct PolicyDecision {
  // What is done.
  Action action = Action::kAllow;
  // What would be done in enforce mode (equals `action` when enforcing).
  Action would_action = Action::kAllow;
  bool enforce = false;
};

class Policy {
 public:
  explicit Policy(PolicySettings settings) : settings_(std::move(settings)) {}

  // `host` is normalized (lowercase, no port).
  PolicyDecision Decide(const Verdict& verdict, std::string_view host) const;
  bool EnforcedFor(std::string_view host) const;
  int block_status() const { return settings_.block_status; }

 private:
  PolicySettings settings_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SCORE_POLICY_H_
