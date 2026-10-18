#ifndef BOT_SHIELD_PROXY_TRANSPORT_H_
#define BOT_SHIELD_PROXY_TRANSPORT_H_

#include <asio/any_io_executor.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>

namespace bot_shield {

// Byte stream the proxy sessions run on (TLS to the client or to Traefik).
// Hides the concrete asio stream type so sessions are not templates.
class Transport {
 public:
  virtual ~Transport() = default;

  virtual asio::awaitable<std::pair<std::error_code, std::size_t>> ReadSome(
      std::span<uint8_t> buffer) = 0;
  virtual asio::awaitable<std::error_code> WriteAll(
      std::span<const uint8_t> data) = 0;
  // Closes the underlying socket; pending operations fail.
  virtual void Close() = 0;
  virtual asio::any_io_executor executor() = 0;
};

template <typename Stream>
class StreamTransport final : public Transport {
 public:
  explicit StreamTransport(Stream stream) : stream_(std::move(stream)) {}

  asio::awaitable<std::pair<std::error_code, std::size_t>> ReadSome(
      std::span<uint8_t> buffer) override {
    auto [ec, n] = co_await stream_.async_read_some(
        asio::buffer(buffer.data(), buffer.size()),
        asio::as_tuple(asio::use_awaitable));
    co_return std::pair{ec, n};
  }

  asio::awaitable<std::error_code> WriteAll(
      std::span<const uint8_t> data) override {
    auto [ec, n] = co_await asio::async_write(
        stream_, asio::buffer(data.data(), data.size()),
        asio::as_tuple(asio::use_awaitable));
    co_return ec;
  }

  void Close() override {
    std::error_code ec;
    stream_.lowest_layer().close(ec);
  }

  asio::any_io_executor executor() override { return stream_.get_executor(); }

  Stream& stream() { return stream_; }

 private:
  Stream stream_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_TRANSPORT_H_
