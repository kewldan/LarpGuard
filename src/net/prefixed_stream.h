#ifndef BOT_SHIELD_NET_PREFIXED_STREAM_H_
#define BOT_SHIELD_NET_PREFIXED_STREAM_H_

#include <asio/associated_executor.hpp>
#include <asio/async_result.hpp>
#include <asio/buffer.hpp>
#include <asio/post.hpp>
#include <cstddef>
#include <cstdint>
#include <system_error>
#include <utility>
#include <vector>

namespace bot_shield {

// Stream adapter that first yields `prefix` (bytes already read from the
// socket, e.g. the ClientHello read for classification) and then reads from
// the wrapped stream. Lets asio::ssl::stream handshake over bytes we have
// consumed. Writes go straight to the wrapped stream.
template <typename NextLayer>
class PrefixedStream {
 public:
  using executor_type = typename NextLayer::executor_type;
  using next_layer_type = NextLayer;
  using lowest_layer_type = typename NextLayer::lowest_layer_type;

  PrefixedStream(NextLayer next, std::vector<uint8_t> prefix)
      : next_(std::move(next)), prefix_(std::move(prefix)) {}

  PrefixedStream(PrefixedStream&&) = default;
  PrefixedStream& operator=(PrefixedStream&&) = default;

  executor_type get_executor() noexcept { return next_.get_executor(); }
  next_layer_type& next_layer() noexcept { return next_; }
  lowest_layer_type& lowest_layer() noexcept { return next_.lowest_layer(); }
  const lowest_layer_type& lowest_layer() const noexcept {
    return next_.lowest_layer();
  }

  template <typename MutableBufferSequence, typename ReadToken>
  auto async_read_some(const MutableBufferSequence& buffers,
                       ReadToken&& token) {
    return asio::async_initiate<ReadToken, void(std::error_code, std::size_t)>(
        [this](auto handler, const MutableBufferSequence& buffers) {
          if (offset_ < prefix_.size()) {
            const std::size_t n =
                asio::buffer_copy(buffers, asio::buffer(prefix_) + offset_);
            offset_ += n;
            if (offset_ == prefix_.size()) {
              prefix_ = {};
              offset_ = 0;
            }
            auto executor =
                asio::get_associated_executor(handler, next_.get_executor());
            asio::post(executor, [handler = std::move(handler), n]() mutable {
              std::move(handler)(std::error_code(), n);
            });
            return;
          }
          next_.async_read_some(buffers, std::move(handler));
        },
        token, buffers);
  }

  template <typename ConstBufferSequence, typename WriteToken>
  auto async_write_some(const ConstBufferSequence& buffers,
                        WriteToken&& token) {
    return next_.async_write_some(buffers, std::forward<WriteToken>(token));
  }

 private:
  NextLayer next_;
  std::vector<uint8_t> prefix_;
  std::size_t offset_ = 0;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_PREFIXED_STREAM_H_
