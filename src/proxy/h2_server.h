#ifndef BOT_SHIELD_PROXY_H2_SERVER_H_
#define BOT_SHIELD_PROXY_H2_SERVER_H_

#include <nghttp2/nghttp2.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>

#include "fp/h2_fingerprint.h"
#include "fp/http_request.h"
#include "proxy/exchange.h"
#include "proxy/h2_connection.h"
#include "proxy/http_message.h"
#include "proxy/proxy_hooks.h"
#include "proxy/transport.h"

namespace bot_shield {

class UpstreamPool;

// Client-facing HTTP/2 server session. Every request becomes an Exchange
// dispatched to the upstream pool; responses stream back with flow control
// tied to what the client has actually received.
class H2ServerConnection final : public H2Connection {
 public:
  static std::shared_ptr<H2ServerConnection> Create(
      std::unique_ptr<Transport> transport, UpstreamPool* pool,
      ClientInfo client, ProxyHooks hooks, const ProxySettings& settings);

  void Start();
  // Stops calling hooks; call before the hook owner goes away.
  void DetachHooks() { hooks_ = ProxyHooks{}; }

  // Akamai-format client fingerprint; empty before the first request.
  const std::string& fingerprint() const { return fingerprint_.fingerprint(); }

 private:
  struct Stream {
    int32_t id = 0;
    ProxyRequest request;
    HttpRequest observed;
    HeaderList trailers;
    std::shared_ptr<Exchange> exchange;
    bool response_submitted = false;
    bool reported = false;
  };

  H2ServerConnection(std::unique_ptr<Transport> transport, UpstreamPool* pool,
                     ClientInfo client, ProxyHooks hooks,
                     const ProxySettings& settings);

  void OnClosed() override;
  bool HasOpenStreams() const override { return !streams_.empty(); }
  void OnBytesRead(std::span<const uint8_t> data) override;
  void OnBytesWritten(std::size_t size) override;

  Stream* FindStream(int32_t id);
  void OnRequestHeaders(Stream& stream, bool end_stream);
  void OnResponseProgress(int32_t id);
  void Report(Stream& stream) const;

  static int OnBeginHeaders(nghttp2_session* session,
                            const nghttp2_frame* frame, void* user_data);
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
  static nghttp2_ssize ReadResponseData(nghttp2_session* session,
                                        int32_t stream_id, uint8_t* buffer,
                                        std::size_t size, uint32_t* data_flags,
                                        nghttp2_data_source* source,
                                        void* user_data);

  UpstreamPool* pool_;
  ClientInfo client_;
  ProxyHooks hooks_;
  H2FingerprintBuilder fingerprint_;
  std::map<int32_t, std::unique_ptr<Stream>> streams_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_H2_SERVER_H_
