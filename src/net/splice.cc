#include "net/splice.h"

#if __linux__
#include <fcntl.h>   // IWYU pragma: keep (splice, pipe2)
#include <unistd.h>  // IWYU pragma: keep (close)

#include <cerrno>        // IWYU pragma: keep
#include <system_error>  // IWYU pragma: keep
#endif

#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>
#include <cstddef>
#include <functional>

namespace bot_shield {
namespace {

#if __linux__
// Bytes per splice: what a default pipe holds (16 pages).
constexpr std::size_t kChunk = std::size_t{64} * 1024;

// The two ends of a pipe, closed on scope exit.
struct Pipe {
  Pipe() {
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) fds[0] = fds[1] = -1;
  }
  ~Pipe() {
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
  }
  Pipe(const Pipe&) = delete;
  Pipe& operator=(const Pipe&) = delete;
  bool ok() const { return fds[0] >= 0; }

  int fds[2] = {-1, -1};
};
#endif

}  // namespace

bool SpliceSupported() {
#if __linux__
  return true;
#else
  return false;
#endif
}

asio::awaitable<SpliceEnd> SpliceStream(
    asio::ip::tcp::socket& from, asio::ip::tcp::socket& to,
    const std::function<void(std::size_t)>& on_bytes) {
#if __linux__
  Pipe pipe;
  if (!pipe.ok()) co_return SpliceEnd::kUnsupported;
  // splice() itself must not block on the sockets: the loop waits.
  std::error_code ec;
  from.native_non_blocking(true, ec);
  if (!ec) to.native_non_blocking(true, ec);
  if (ec) co_return SpliceEnd::kUnsupported;
  constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
  const unsigned flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
  while (true) {
    const ssize_t in = splice(from.native_handle(), nullptr, pipe.fds[1],
                              nullptr, kChunk, flags);
    if (in == 0) co_return SpliceEnd::kEof;
    if (in < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) co_return SpliceEnd::kError;
      auto [wait_ec] =
          co_await from.async_wait(asio::ip::tcp::socket::wait_read, kUse);
      if (wait_ec) co_return SpliceEnd::kError;
      continue;
    }
    // Everything taken into the pipe goes out before reading more.
    auto left = static_cast<std::size_t>(in);
    while (left > 0) {
      const ssize_t out = splice(pipe.fds[0], nullptr, to.native_handle(),
                                 nullptr, left, flags);
      if (out > 0) {
        left -= static_cast<std::size_t>(out);
        continue;
      }
      if (out < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        auto [wait_ec] =
            co_await to.async_wait(asio::ip::tcp::socket::wait_write, kUse);
        if (wait_ec) co_return SpliceEnd::kError;
        continue;
      }
      co_return SpliceEnd::kError;
    }
    on_bytes(static_cast<std::size_t>(in));
  }
#else
  (void)from;
  (void)to;
  (void)on_bytes;
  co_return SpliceEnd::kUnsupported;
#endif
}

}  // namespace bot_shield
