#ifndef BOT_SHIELD_WATCHDOG_FAIL_OPEN_H_
#define BOT_SHIELD_WATCHDOG_FAIL_OPEN_H_

#include <chrono>
#include <optional>
#include <string>

#include "config/config.h"

namespace bot_shield {

// Fail-open switch of bot-shield-watchdog (ADR-012): after `fail_after`
// failed health checks in a row traffic goes straight to Traefik ("open");
// after `recover_after` good ones it goes back through the gateway. The
// initial state is unknown, so the first decision is always applied (a
// redirect left behind by a crashed watchdog is removed).
class FailOpenSwitch {
 public:
  enum class Change { kNone, kOpen, kClose };

  FailOpenSwitch(int fail_after, int recover_after)
      : fail_after_(fail_after), recover_after_(recover_after) {}

  // Records one check; returns the change to apply. Call Applied() once
  // the change took effect, otherwise it is returned again next time.
  Change Observe(bool healthy);
  void Applied(Change change);

  // nullopt until the first change was applied.
  std::optional<bool> open() const { return open_; }

 private:
  int fail_after_;
  int recover_after_;
  int failures_ = 0;
  int successes_ = 0;
  std::optional<bool> open_;
};

// GET http://<endpoint>/health; true on a 200 answer within `timeout`.
// `detail` gets the status line or the error.
bool ProbeHealth(const Endpoint& endpoint, std::chrono::milliseconds timeout,
                 std::string* detail);

}  // namespace bot_shield

#endif  // BOT_SHIELD_WATCHDOG_FAIL_OPEN_H_
