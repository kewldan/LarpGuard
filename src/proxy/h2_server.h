#ifndef BOT_SHIELD_PROXY_H2_SERVER_H_
#define BOT_SHIELD_PROXY_H2_SERVER_H_

#include <nghttp2/nghttp2.h>

#include <asio/steady_timer.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>

#include "fp/h2_fingerprint.h"
#include "fp/http_request.h"
#include "net/watchdog.h"
#include "proxy/body_rate.h"
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
    // Minimum body rate while the request body is still arriving.
    BodyRate body_rate;
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
  void OnInputProcessed() override;

  // True until the first request's headers are complete, and while a later
  // header block (HEADERS + CONTINUATION) is incomplete.
  bool AwaitingHeaders() const {
    return requests_ == 0 || header_block_stream_ != 0;
  }
  // Arms or disarms the request_headers deadline to match AwaitingHeaders().
  void UpdateHeadersDeadline();
  // Charges streams waiting for request body bytes once a second and resets
  // those below the minimum rate.
  void ArmBodyTimer();
  void CheckBodyRates();

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
  static int OnInvalidFrameRecv(nghttp2_session* session,
                                const nghttp2_frame* frame, int error_code,
                                void* user_data);
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
  ProxySettings settings_;
  H2FingerprintBuilder fingerprint_;
  // Requests accepted on this connection (max_requests_per_connection).
  std::size_t requests_ = 0;
  // Stream whose header block has begun but not ended; 0 if none.
  int32_t header_block_stream_ = 0;
  std::shared_ptr<Watchdog> headers_deadline_;
  asio::steady_timer body_timer_;
  std::chrono::steady_clock::time_point body_tick_;
  bool body_timer_armed_ = false;
  std::map<int32_t, std::unique_ptr<Stream>> streams_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_H2_SERVER_H_
