#ifndef BOT_SHIELD_PROXY_NOTIFIER_H_
#define BOT_SHIELD_PROXY_NOTIFIER_H_

#include <asio/any_io_executor.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

namespace bot_shield {

// Wakes one waiting coroutine. A Notify() with nobody waiting is remembered,
// so a wake-up between "check state" and "wait" is never lost. Single-threaded
// (one io_context per worker).
class Notifier {
 public:
  explicit Notifier(const asio::any_io_executor& executor) : timer_(executor) {}

  void Notify() {
    pending_ = true;
    timer_.cancel();
  }

  asio::awaitable<void> Wait() {
    if (!pending_) {
      timer_.expires_at(asio::steady_timer::time_point::max());
      co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
    }
    pending_ = false;
  }

 private:
  asio::steady_timer timer_;
  bool pending_ = false;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_NOTIFIER_H_
