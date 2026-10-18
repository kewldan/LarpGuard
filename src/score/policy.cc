#include "score/policy.h"

#include <optional>
#include <string_view>

#include "common/host.h"
#include "score/scorer.h"

namespace bot_shield {

std::string_view ActionName(Action action) {
  switch (action) {
    case Action::kAllow:
      return "allow";
    case Action::kChallenge:
      return "challenge";
    case Action::kBlock:
      return "block";
    case Action::kTarpit:
      return "tarpit";
    case Action::kDecoy:
      return "decoy";
  }
  return "?";
}

bool ParseAction(std::string_view text, Action* action) {
  if (text == "allow") {
    *action = Action::kAllow;
  } else if (text == "block") {
    *action = Action::kBlock;
  } else if (text == "challenge") {
    *action = Action::kChallenge;
  } else if (text == "tarpit") {
    *action = Action::kTarpit;
  } else if (text == "decoy") {
    *action = Action::kDecoy;
  } else {
    return false;
  }
  return true;
}

std::string_view HostModeName(HostMode mode) {
  switch (mode) {
    case HostMode::kShadow:
      return "shadow";
    case HostMode::kEnforce:
      return "enforce";
    case HostMode::kOff:
      return "off";
  }
  return "?";
}

bool ParseHostMode(std::string_view text, HostMode* mode) {
  if (text == "shadow") {
    *mode = HostMode::kShadow;
  } else if (text == "enforce") {
    *mode = HostMode::kEnforce;
  } else if (text == "off") {
    *mode = HostMode::kOff;
  } else {
    return false;
  }
  return true;
}

ModeResolution Policy::ResolveMode(std::string_view host,
                                   std::optional<HostMode> label_mode) const {
  // Exact names win over wildcards, configuration over labels.
  for (const auto& [pattern, mode] : settings_.host_modes) {
    if (pattern == host) return {mode, "policy.hosts"};
  }
  for (const auto& [pattern, mode] : settings_.host_modes) {
    if (pattern.starts_with("*.") && HostMatches(pattern, host)) {
      return {mode, "policy.hosts"};
    }
  }
  if (label_mode) return {*label_mode, "labels"};
  return {settings_.enforce ? HostMode::kEnforce : HostMode::kShadow, "mode"};
}

PolicyDecision Policy::Decide(const Verdict& verdict, HostMode mode,
                              std::optional<Action> override_action) const {
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
    case BotClass::kVerifiedBot:
      decision.would_action = settings_.verified_bot_action;
      break;
  }
  if (override_action) decision.would_action = *override_action;
  decision.enforce = mode == HostMode::kEnforce;
  decision.action = decision.enforce ? decision.would_action : Action::kAllow;
  return decision;
}

}  // namespace bot_shield
