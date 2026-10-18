#include "ratelimit/gcra.h"

#include <algorithm>
#include <cstdint>

namespace bot_shield {

GcraParams GcraParams::FromRate(int64_t count, int64_t period_ns,
                                int64_t burst) {
  GcraParams params;
  params.emission_ns =
      std::max<int64_t>(1, period_ns / std::max<int64_t>(1, count));
  params.tolerance_ns = params.emission_ns * (std::max<int64_t>(1, burst) - 1);
  return params;
}

GcraResult GcraCheck(int64_t* tat, int64_t now_ns, const GcraParams& params) {
  GcraResult result;
  const int64_t current = std::max(*tat, now_ns);
  const int64_t allow_at = current - params.tolerance_ns;
  if (now_ns < allow_at) {
    result.allowed = false;
    result.retry_after_ns = allow_at - now_ns;
    result.reset_after_ns = current - now_ns;
    return result;
  }
  const int64_t next = current + params.emission_ns;
  *tat = next;
  result.allowed = true;
  // Emissions that still fit into the tolerance window.
  result.remaining =
      (now_ns + params.tolerance_ns + params.emission_ns - next) /
      params.emission_ns;
  result.reset_after_ns = next - now_ns;
  return result;
}

}  // namespace bot_shield
