#include "proxy/body_rate.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bot_shield {

BodyRate::BodyRate(std::chrono::milliseconds grace, int64_t min_rate)
    : grace_us_(
          std::chrono::duration_cast<std::chrono::microseconds>(grace).count()),
      min_rate_(min_rate),
      budget_us_(grace_us_) {}

std::chrono::milliseconds BodyRate::remaining() const {
  // Rounded up, so a timer armed with it fires after the budget is gone.
  return std::chrono::milliseconds((std::max<int64_t>(budget_us_, 0) + 999) /
                                   1000);
}

void BodyRate::Received(std::size_t bytes) {
  if (!enabled() || bytes == 0) return;
  // 1 s per min_rate bytes; capped first so the product cannot overflow.
  const auto capped = static_cast<int64_t>(
      std::min<std::size_t>(bytes, static_cast<std::size_t>(INT32_MAX)));
  budget_us_ = std::min(grace_us_, budget_us_ + capped * 1'000'000 / min_rate_);
}

bool BodyRate::Charge(std::chrono::steady_clock::duration waited) {
  if (!enabled()) return false;
  budget_us_ -=
      std::chrono::duration_cast<std::chrono::microseconds>(waited).count();
  return expired();
}

bool BodyRateExempt(std::string_view content_type) {
  return content_type.starts_with("application/grpc");
}

}  // namespace bot_shield
