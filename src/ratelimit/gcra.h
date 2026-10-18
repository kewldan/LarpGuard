#ifndef BOT_SHIELD_RATELIMIT_GCRA_H_
#define BOT_SHIELD_RATELIMIT_GCRA_H_

#include <cstdint>

namespace bot_shield {

// Generic Cell Rate Algorithm parameters for "count per period, burst b".
struct GcraParams {
  // Time between two requests at the sustained rate.
  int64_t emission_ns = 0;
  // How far ahead of schedule a client may run: (burst - 1) emissions.
  int64_t tolerance_ns = 0;

  // `count` requests per `period_ns`, up to `burst` at once (>= 1).
  static GcraParams FromRate(int64_t count, int64_t period_ns, int64_t burst);
};

struct GcraResult {
  bool allowed = false;
  // Requests still allowed right now.
  int64_t remaining = 0;
  // When the next request is allowed (0 if it is allowed now).
  int64_t retry_after_ns = 0;
  // When the bucket is back to a full burst.
  int64_t reset_after_ns = 0;
};

// One GCRA step. `tat` is the key's theoretical arrival time (0 for a new
// key) and is advanced only when the request is allowed. Times are in
// nanoseconds on a monotonic clock.
GcraResult GcraCheck(int64_t* tat, int64_t now_ns, const GcraParams& params);

}  // namespace bot_shield

#endif  // BOT_SHIELD_RATELIMIT_GCRA_H_
