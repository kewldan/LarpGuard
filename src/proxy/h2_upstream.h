#ifndef BOT_SHIELD_PROXY_H2_UPSTREAM_H_
#define BOT_SHIELD_PROXY_H2_UPSTREAM_H_

#include <nghttp2/nghttp2.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>

#include "proxy/exchange.h"
#include "proxy/h2_connection.h"
#include "proxy/http_message.h"
#include "proxy/transport.h"

namespace bot_shield {

// HTTP/2 client session to Traefik, multiplexing exchanges as streams.
class H2UpstreamConnection final : public H2Connection {
 public:
  static std::shared_ptr<H2UpstreamConnection> Create(
      std::unique_ptr<Transport> transport,
      std::chrono::milliseconds idle_timeout);

  void Start();
  void Submit(const std::shared_ptr<Exchange>& exchange);

  // New streams can be opened (not closed, no GOAWAY received).
  bool usable() const { return !closed() && !goaway_; }
  std::size_t open_streams() const { return streams_.size(); }

 private:
  struct Stream {
    int32_t id = 0;
    std::shared_ptr<Exchange> exchange;
    ProxyResponse response;
    HeaderList trailers;
  };

  H2UpstreamConnection(std::unique_ptr<Transport> transport,
                       std::chrono::milliseconds idle_timeout);

  void OnClosed() override;
  bool HasOpenStreams() const override { return !streams_.empty(); }
  Stream* FindStream(int32_t id);

  static int OnHeader(nghttp2_session* session, const nghttp2_frame* frame,
                      const uint8_t* name, std::size_t name_size,
                      const uint8_t* value, std::size_t value_size,
                      uint8_t flags, void* user_data);
  static int OnFrameRecv(nghttp2_session* session, const nghttp2_frame* frame,
                         void* user_data);
  static int OnDataChunk(nghttp2_session* session, uint8_t flags,
                         int32_t stream_id, const uint8_t* data,
                         std::size_t size, void* user_data);
  static int OnStreamClose(nghttp2_session* session, int32_t stream_id,
                           uint32_t error_code, void* user_data);
  static nghttp2_ssize ReadRequestData(nghttp2_session* session,
                                       int32_t stream_id, uint8_t* buffer,
                                       std::size_t size, uint32_t* data_flags,
                                       nghttp2_data_source* source,
                                       void* user_data);

  std::map<int32_t, std::unique_ptr<Stream>> streams_;
  bool goaway_ = false;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_H2_UPSTREAM_H_
