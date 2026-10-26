#ifndef BOT_SHIELD_NET_SPLICE_H_
#define BOT_SHIELD_NET_SPLICE_H_

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <cstddef>
#include <functional>

namespace bot_shield {

// How a spliced direction ended.
enum class SpliceEnd { kEof, kError, kUnsupported };

// Whether SpliceStream can work here (Linux with splice(2) and pipes).
bool SpliceSupported();

// Moves bytes `from` -> `to` inside the kernel, through a pipe with
// splice(2), until end of stream or an error: no copy through user space,
// for relays where nothing reads the bytes (TLS passthrough). `on_bytes`
// runs after each forwarded chunk. kUnsupported (before moving anything)
// when splice is not available; then copy the usual way.
asio::awaitable<SpliceEnd> SpliceStream(
    asio::ip::tcp::socket& from, asio::ip::tcp::socket& to,
    const std::function<void(std::size_t)>& on_bytes);

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_SPLICE_H_
