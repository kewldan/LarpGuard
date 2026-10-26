#ifndef BOT_SHIELD_PROXY_BODY_RATE_H_
#define BOT_SHIELD_PROXY_BODY_RATE_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bot_shield {

// Minimum request body rate (slow POST), in the spirit of Apache's
// mod_reqtimeout MinRate: a body starts with `grace` of time, every
// `min_rate` bytes received buy one more second, and the budget never
// grows above `grace`. Only time spent waiting for the client is charged:
// while the gateway holds body bytes the upstream has not taken yet
// (backpressure), the caller does not charge.
class BodyRate {
 public:
  BodyRate() = default;  // Disabled: never expires.
  BodyRate(std::chrono::milliseconds grace, int64_t min_rate);

  bool enabled() const { return min_rate_ > 0; }
  bool expired() const { return enabled() && budget_us_ <= 0; }
  // Time left before the budget is spent if no byte arrives.
  std::chrono::milliseconds remaining() const;

  void Received(std::size_t bytes);
  // Charges client time; true once the budget is spent.
  bool Charge(std::chrono::steady_clock::duration waited);

 private:
  int64_t grace_us_ = 0;
  int64_t min_rate_ = 0;
  int64_t budget_us_ = 0;
};

// Bodies exempt from the minimum rate: gRPC streams send messages when
// the application has them, not at a steady rate.
bool BodyRateExempt(std::string_view content_type);

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_BODY_RATE_H_
