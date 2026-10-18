#include "score/policy.h"

#include <string_view>

#include "common/host.h"
#include "score/scorer.h"

namespace bot_shield {

std::string_view ActionName(Action action) {
  switch (action) {
    case Action::kAllow:
      return "allow";
    case Action::kBlock:
      return "block";
  }
  return "?";
}

bool ParseAction(std::string_view text, Action* action) {
  if (text == "allow") {
    *action = Action::kAllow;
  } else if (text == "block") {
    *action = Action::kBlock;
  } else {
    return false;
  }
  return true;
}

bool Policy::EnforcedFor(std::string_view host) const {
  // Exact names win over wildcards, wildcards over the global mode.
  for (const auto& [pattern, enforce] : settings_.host_modes) {
    if (pattern == host) return enforce;
  }
  for (const auto& [pattern, enforce] : settings_.host_modes) {
    if (pattern.starts_with("*.") && HostMatches(pattern, host)) {
      return enforce;
    }
  }
  return settings_.enforce;
}

PolicyDecision Policy::Decide(const Verdict& verdict,
                              std::string_view host) const {
  PolicyDecision decision;
  switch (verdict.bot_class) {
    case BotClass::kHuman:
      decision.would_action = Action::kAllow;
      break;
    case BotClass::kSuspicious:
      decision.would_action = settings_.suspicious_action;
      break;
    case BotClass::kBot:
      decision.would_action = settings_.bot_action;
      break;
  }
  decision.enforce = EnforcedFor(host);
  decision.action = decision.enforce ? decision.would_action : Action::kAllow;
  return decision;
}

}  // namespace bot_shield
