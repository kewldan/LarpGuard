#ifndef BOT_SHIELD_NET_WATCHDOG_H_
#define BOT_SHIELD_NET_WATCHDOG_H_

#include <asio/any_io_executor.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <system_error>

namespace bot_shield {

// Calls `on_expire` once if Touch() has not been called for `timeout`.
// Used both as a fixed deadline (never touched) and as an idle timer. The
// callback usually closes sockets, which makes pending operations fail.
//
// Not thread-safe: use from the strand / single-threaded io_context that owns
// the connection.
class Watchdog : public std::enable_shared_from_this<Watchdog> {
 public:
  using Clock = std::chrono::steady_clock;

  static std::shared_ptr<Watchdog> Create(const asio::any_io_executor& executor,
                                          Clock::duration timeout,
                                          std::function<void()> on_expire);

  Watchdog(const Watchdog&) = delete;
  Watchdog& operator=(const Watchdog&) = delete;

  void Touch() { last_activity_ = Clock::now(); }
  // Disarms the watchdog; `on_expire` will not be called afterwards.
  void Stop() noexcept;
  bool expired() const { return expired_; }

 private:
  Watchdog(const asio::any_io_executor& executor, Clock::duration timeout,
           std::function<void()> on_expire);

  void Arm(Clock::duration delay);
  void OnTimer(const std::error_code& ec);

  asio::steady_timer timer_;
  const Clock::duration timeout_;
  std::function<void()> on_expire_;
  Clock::time_point last_activity_;
  bool stopped_ = false;
  bool expired_ = false;
};

// Stops the watchdog when leaving scope, so `on_expire` never outlives the
// objects it references.
class ScopedWatchdog {
 public:
  ScopedWatchdog(const asio::any_io_executor& executor,
                 Watchdog::Clock::duration timeout,
                 std::function<void()> on_expire)
      : watchdog_(Watchdog::Create(executor, timeout, std::move(on_expire))) {}
  ~ScopedWatchdog() { watchdog_->Stop(); }

  ScopedWatchdog(const ScopedWatchdog&) = delete;
  ScopedWatchdog& operator=(const ScopedWatchdog&) = delete;

  Watchdog& operator*() const { return *watchdog_; }
  Watchdog* operator->() const { return watchdog_.get(); }

 private:
  std::shared_ptr<Watchdog> watchdog_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_WATCHDOG_H_
