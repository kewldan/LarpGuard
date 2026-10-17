#include "net/watchdog.h"

#include <asio/error.hpp>
#include <utility>

namespace bot_shield {

std::shared_ptr<Watchdog> Watchdog::Create(
    const asio::any_io_executor& executor, Clock::duration timeout,
    std::function<void()> on_expire) {
  std::shared_ptr<Watchdog> watchdog(
      new Watchdog(executor, timeout, std::move(on_expire)));
  watchdog->Arm(timeout);
  return watchdog;
}

Watchdog::Watchdog(const asio::any_io_executor& executor,
                   Clock::duration timeout, std::function<void()> on_expire)
    : timer_(executor),
      timeout_(timeout),
      on_expire_(std::move(on_expire)),
      last_activity_(Clock::now()) {}

void Watchdog::Stop() noexcept {
  stopped_ = true;
  on_expire_ = nullptr;
  try {
    timer_.cancel();
  } catch (const std::system_error&) {  // NOLINT(bugprone-empty-catch)
    // The pending wait still finds stopped_ set and does nothing.
  }
}

void Watchdog::Arm(Clock::duration delay) {
  timer_.expires_after(delay);
  timer_.async_wait([self = shared_from_this()](const std::error_code& ec) {
    self->OnTimer(ec);
  });
}

void Watchdog::OnTimer(const std::error_code& ec) {
  if (stopped_ || ec == asio::error::operation_aborted) return;
  const Clock::duration idle = Clock::now() - last_activity_;
  if (idle < timeout_) {
    Arm(timeout_ - idle);
    return;
  }
  stopped_ = true;
  expired_ = true;
  auto on_expire = std::move(on_expire_);
  if (on_expire) on_expire();
}

}  // namespace bot_shield
