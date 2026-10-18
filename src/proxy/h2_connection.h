#ifndef BOT_SHIELD_PROXY_H2_CONNECTION_H_
#define BOT_SHIELD_PROXY_H2_CONNECTION_H_

#include <nghttp2/nghttp2.h>

#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "proxy/http_message.h"
#include "proxy/notifier.h"
#include "proxy/transport.h"

namespace bot_shield {

// Shared I/O for nghttp2 sessions on a Transport: a read loop feeding the
// session, a write loop draining it, deferred flushing (nghttp2 must not be
// re-entered from its own callbacks) and an idle timeout that only fires
// while no stream is open. Subclasses create `session_` and implement the
// stream logic.
class H2Connection : public std::enable_shared_from_this<H2Connection> {
 public:
  virtual ~H2Connection();

  H2Connection(const H2Connection&) = delete;
  H2Connection& operator=(const H2Connection&) = delete;

  // Closes the socket and fails all streams. Idempotent.
  void Close();
  bool closed() const { return closed_; }

  // Completes once the connection is closed and its streams were failed.
  asio::awaitable<void> WaitClosed();

 protected:
  H2Connection(std::unique_ptr<Transport> transport,
               std::chrono::milliseconds idle_timeout);

  // Starts the read, write and idle loops. `session_` must exist.
  void StartIo();
  // Schedules a write pass; safe to call from nghttp2 callbacks.
  void Flush();

  virtual void OnClosed() = 0;
  virtual bool HasOpenStreams() const = 0;
  virtual void OnBytesRead(std::span<const uint8_t> /*data*/) {}
  virtual void OnBytesWritten(std::size_t /*size*/) {}

  // nghttp2 name/value pairs pointing into `headers` (kept alive by caller).
  static std::vector<nghttp2_nv> MakeNva(
      const std::vector<std::pair<std::string, std::string>>& headers);

  nghttp2_session* session_ = nullptr;
  std::unique_ptr<Transport> transport_;

 private:
  asio::awaitable<void> ReadLoop();
  asio::awaitable<void> WriteLoop();
  asio::awaitable<void> IdleLoop();
  void CloseIfDone();

  const std::chrono::milliseconds idle_timeout_;
  std::chrono::steady_clock::time_point last_activity_;
  asio::steady_timer idle_timer_;
  Notifier closed_notifier_;
  bool writing_ = false;
  bool read_done_ = false;
  bool closed_ = false;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_H2_CONNECTION_H_
