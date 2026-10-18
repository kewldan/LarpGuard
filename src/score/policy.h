#ifndef BOT_SHIELD_SCORE_POLICY_H_
#define BOT_SHIELD_SCORE_POLICY_H_

#include <optional>
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

// How the gateway treats a host: verdicts only (shadow), verdicts carried
// out (enforce), or plain proxying without verdicts and limits (off).
enum class HostMode { kShadow, kEnforce, kOff };

std::string_view HostModeName(HostMode mode);
bool ParseHostMode(std::string_view text, HostMode* mode);

struct PolicySettings {
  // Shadow mode computes verdicts but never acts on them.
  bool enforce = false;
  int suspicious_threshold = 30;
  int bot_threshold = 70;
  Action suspicious_action = Action::kAllow;
  Action bot_action = Action::kBlock;
  int block_status = 403;
  // Per-host mode overrides: exact names or "*.parent".
  std::vector<std::pair<std::string, HostMode>> host_modes;
};

// A host's mode and where it came from: "policy.hosts", "labels" or
// "mode" (the global setting).
struct ModeResolution {
  HostMode mode = HostMode::kShadow;
  std::string_view source;
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

  // Mode of `host` (normalized, no port): configured host overrides win,
  // then `label_mode` (docker labels), then the global mode.
  HostMode ModeFor(std::string_view host,
                   std::optional<HostMode> label_mode = std::nullopt) const {
    return ResolveMode(host, label_mode).mode;
  }
  ModeResolution ResolveMode(
      std::string_view host,
      std::optional<HostMode> label_mode = std::nullopt) const;
  bool global_enforce() const { return settings_.enforce; }

  // `override_action` (from an allow/block rule) replaces the action of the
  // verdict's class; `mode` decides whether it is carried out.
  PolicyDecision Decide(
      const Verdict& verdict, HostMode mode,
      std::optional<Action> override_action = std::nullopt) const;
  PolicyDecision Decide(
      const Verdict& verdict, std::string_view host,
      std::optional<Action> override_action = std::nullopt) const {
    return Decide(verdict, ModeFor(host), override_action);
  }
  bool EnforcedFor(std::string_view host) const {
    return ModeFor(host) == HostMode::kEnforce;
  }
  int block_status() const { return settings_.block_status; }

 private:
  PolicySettings settings_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SCORE_POLICY_H_
