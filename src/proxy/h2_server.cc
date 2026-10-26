#include "proxy/h2_server.h"

#include <nghttp2/nghttp2.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/metrics.h"
#include "net/watchdog.h"
#include "proxy/body_rate.h"
#include "proxy/exchange.h"
#include "proxy/h2_connection.h"
#include "proxy/http_message.h"
#include "proxy/proxy_hooks.h"
#include "proxy/transport.h"
#include "proxy/upstream_pool.h"

namespace bot_shield {
namespace {

constexpr uint32_t kMaxConcurrentStreams = 100;
constexpr uint32_t kInitialWindowSize = 1 << 20;
constexpr int32_t kConnectionWindowSize = 1 << 24;
constexpr uint32_t kMaxHeaderListSize = 64 * 1024;
// Flood limits, set explicitly rather than relying on nghttp2's defaults.
// Rapid reset (CVE-2023-44487): RST_STREAM from the client drains a token
// bucket; when it is empty nghttp2 sends GOAWAY. Browsers cancel a few
// streams on navigation, never hundreds.
constexpr uint64_t kStreamResetBurst = 200;
constexpr uint64_t kStreamResetRate = 33;
// CONTINUATION flood (CVE-2024-27316 and relatives): frames per header block.
constexpr std::size_t kMaxContinuations = 8;
// Pending SETTINGS/PING ACKs (SETTINGS and PING floods).
constexpr std::size_t kMaxOutboundAck = 1000;
constexpr std::size_t kMaxSettingsEntries = 32;
constexpr std::chrono::seconds kBodyRateTick{1};
constexpr std::string_view kBadGateway = "bad gateway\n";
constexpr std::string_view kMethodNotAllowed = "method not allowed\n";

std::string ToString(const uint8_t* data, std::size_t size) {
  return {reinterpret_cast<const char*>(data), size};
}

}  // namespace

int64_t SteadyMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

std::shared_ptr<H2ServerConnection> H2ServerConnection::Create(
    std::unique_ptr<Transport> transport, UpstreamPool* pool, ClientInfo client,
    ProxyHooks hooks, const ProxySettings& settings) {
  return std::shared_ptr<H2ServerConnection>(
      new H2ServerConnection(std::move(transport), pool, std::move(client),
                             std::move(hooks), settings));
}

H2ServerConnection::H2ServerConnection(std::unique_ptr<Transport> transport,
                                       UpstreamPool* pool, ClientInfo client,
                                       ProxyHooks hooks,
                                       const ProxySettings& settings)
    : H2Connection(std::move(transport), settings.idle_timeout),
      pool_(pool),
      client_(std::move(client)),
      hooks_(std::move(hooks)),
      settings_(settings),
      body_timer_(transport_->executor()) {
  nghttp2_session_callbacks* callbacks = nullptr;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          &OnBeginHeaders);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, &OnHeader);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &OnFrameRecv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                            &OnDataChunk);
  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
      callbacks, &OnInvalidFrameRecv);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                         &OnStreamClose);
  nghttp2_option* option = nullptr;
  nghttp2_option_new(&option);
  // Window updates follow what the upstream actually consumed.
  nghttp2_option_set_no_auto_window_update(option, 1);
  nghttp2_option_set_stream_reset_rate_limit(option, kStreamResetBurst,
                                             kStreamResetRate);
  nghttp2_option_set_max_continuations(option, kMaxContinuations);
  nghttp2_option_set_max_outbound_ack(option, kMaxOutboundAck);
  nghttp2_option_set_max_settings(option, kMaxSettingsEntries);
  nghttp2_session_server_new2(&session_, callbacks, this, option);
  nghttp2_option_del(option);
  nghttp2_session_callbacks_del(callbacks);
}

void H2ServerConnection::Start() {
  const std::array<nghttp2_settings_entry, 3> settings = {{
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kMaxConcurrentStreams},
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, kInitialWindowSize},
      {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, kMaxHeaderListSize},
  }};
  nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings.data(),
                          settings.size());
  nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0,
                                        kConnectionWindowSize);
  UpdateHeadersDeadline();
  StartIo();
}

void H2ServerConnection::OnInputProcessed() { UpdateHeadersDeadline(); }

void H2ServerConnection::UpdateHeadersDeadline() {
  if (closed()) return;
  if (!AwaitingHeaders()) {
    if (headers_deadline_) {
      headers_deadline_->Stop();
      headers_deadline_.reset();
    }
    return;
  }
  if (headers_deadline_) return;
  std::weak_ptr<H2Connection> weak = weak_from_this();
  headers_deadline_ = Watchdog::Create(
      transport_->executor(), settings_.request_headers_timeout, [weak] {
        auto self = weak.lock();
        if (!self || self->closed()) return;
        auto* server = static_cast<H2ServerConnection*>(self.get());
        if (!server->AwaitingHeaders()) return;
        GlobalMetrics().request_header_timeouts.Inc();
        server->Close();
      });
}

void H2ServerConnection::ArmBodyTimer() {
  if (body_timer_armed_ || closed()) return;
  body_timer_armed_ = true;
  body_tick_ = std::chrono::steady_clock::now();
  body_timer_.expires_after(kBodyRateTick);
  body_timer_.async_wait([weak = weak_from_this()](const std::error_code& ec) {
    auto self = weak.lock();
    if (!self) return;
    auto* server = static_cast<H2ServerConnection*>(self.get());
    server->body_timer_armed_ = false;
    if (ec || server->closed()) return;
    server->CheckBodyRates();
  });
}

void H2ServerConnection::CheckBodyRates() {
  const auto waited = std::chrono::steady_clock::now() - body_tick_;
  bool pending = false;
  for (auto& [id, stream] : streams_) {
    if (!stream->body_rate.enabled() || !stream->exchange) continue;
    const Exchange& exchange = *stream->exchange;
    if (exchange.request_ended) {
      stream->body_rate = BodyRate();
      continue;
    }
    pending = true;
    // Bytes the upstream has not taken yet: the client is not the one
    // being waited for.
    if (!exchange.request_body.empty()) continue;
    if (stream->body_rate.Charge(waited)) {
      GlobalMetrics().request_body_timeouts.Inc();
      stream->body_rate = BodyRate();
      nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, id,
                                NGHTTP2_CANCEL);
    }
  }
  Flush();
  if (pending) ArmBodyTimer();
}

void H2ServerConnection::OnBytesRead(std::span<const uint8_t> data) {
  if (hooks_.on_client_bytes) hooks_.on_client_bytes(data);
}

void H2ServerConnection::OnBytesWritten(std::size_t size) {
  if (hooks_.on_bytes_to_client) hooks_.on_bytes_to_client(size);
}

H2ServerConnection::Stream* H2ServerConnection::FindStream(int32_t id) {
  const auto it = streams_.find(id);
  return it == streams_.end() ? nullptr : it->second.get();
}

void H2ServerConnection::Report(Stream& stream) const {
  if (stream.reported || !stream.exchange) return;
  stream.reported = true;
  if (stream.exchange->local) {
    GlobalMetrics().local_responses.Inc();
  } else {
    GlobalMetrics().proxied_requests.Inc();
  }
  if (hooks_.on_done) hooks_.on_done(*stream.exchange);
}

void H2ServerConnection::OnClosed() {
  if (headers_deadline_) {
    headers_deadline_->Stop();
    headers_deadline_.reset();
  }
  body_timer_.cancel();
  for (auto& [id, stream] : streams_) {
    if (stream->exchange) {
      if (!stream->exchange->response_ended) {
        stream->exchange->CancelFromClient();
      }
      Report(*stream);
    }
  }
  streams_.clear();
}

void H2ServerConnection::OnRequestHeaders(Stream& stream, bool end_stream) {
  if (requests_ >= settings_.max_requests_per_connection) {
    // Arrived before the client saw our GOAWAY.
    nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, stream.id,
                              NGHTTP2_REFUSED_STREAM);
    return;
  }
  if (++requests_ == settings_.max_requests_per_connection) {
    // Graceful: streams up to this one finish, the client reconnects.
    GlobalMetrics().connection_request_limits.Inc();
    nghttp2_submit_goaway(session_, NGHTTP2_FLAG_NONE, stream.id,
                          NGHTTP2_NO_ERROR, nullptr, 0);
  }
  if (!fingerprint_.complete()) {
    fingerprint_.OnFirstRequest(stream.observed.pseudo_header_order);
  }
  auto exchange = std::make_shared<Exchange>();
  exchange->started_ms = SteadyMillis();
  exchange->request = std::move(stream.request);
  if (exchange->request.authority.empty()) {
    exchange->request.authority =
        std::string(FindHeader(exchange->request.headers, "host"));
  }
  exchange->request.headers = FilterRequestHeaders(exchange->request.headers);
  AddForwardingHeaders(client_, exchange->request.authority,
                       &exchange->request.headers);
  exchange->observed = std::move(stream.observed);
  exchange->h2_fingerprint = fingerprint_.fingerprint();
  exchange->request_ended = end_stream;
  if (!end_stream &&
      !BodyRateExempt(FindHeader(exchange->request.headers, "content-type"))) {
    stream.body_rate = BodyRate(settings_.request_body_timeout,
                                settings_.request_body_min_rate);
    if (stream.body_rate.enabled()) ArmBodyTimer();
  }

  const int32_t id = stream.id;
  std::weak_ptr<H2Connection> weak = weak_from_this();
  exchange->wake_client = [weak, id] {
    if (auto self = weak.lock()) {
      static_cast<H2ServerConnection*>(self.get())->OnResponseProgress(id);
    }
  };
  exchange->request_consumed = [weak, id](std::size_t size) {
    auto self = weak.lock();
    if (!self || self->closed()) return;
    auto* server = static_cast<H2ServerConnection*>(self.get());
    nghttp2_session_consume(server->session_, id, size);
    server->Flush();
  };
  stream.exchange = exchange;

  if (exchange->request.method == "CONNECT") {
    exchange->RespondLocally(405, kMethodNotAllowed);
    return;
  }
  exchange->dispatch = [pool = pool_, name = client_.server_name,
                        weak = std::weak_ptr<Exchange>(exchange)] {
    if (auto held = weak.lock()) pool->Dispatch(name, held);
  };
  if (hooks_.on_request) hooks_.on_request(*exchange);
  if (!exchange->local && !exchange->dispatch_held) {
    pool_->Dispatch(client_.server_name, exchange);
  }
}

void H2ServerConnection::OnResponseProgress(int32_t id) {
  if (closed()) return;
  Stream* stream = FindStream(id);
  if (stream == nullptr || !stream->exchange) return;
  Exchange& exchange = *stream->exchange;

  if (!stream->response_submitted) {
    if (exchange.upstream_failed && !exchange.response_started) {
      // Re-enters this function through wake_client.
      exchange.RespondLocally(502, kBadGateway);
      return;
    }
    if (!exchange.response_started) return;
    stream->response_submitted = true;

    HeaderList headers = {
        {":status", std::to_string(exchange.response.status)}};
    for (auto& header : FilterResponseHeaders(exchange.response.headers)) {
      headers.push_back(std::move(header));
    }
    SetAltSvc(settings_.alt_svc, &headers);
    const std::vector<nghttp2_nv> nva = MakeNva(headers);
    const bool no_body = exchange.response_ended &&
                         exchange.response_body.empty() &&
                         exchange.response_trailers.empty();
    nghttp2_data_provider2 provider{};
    provider.source.ptr = stream;
    provider.read_callback = &ReadResponseData;
    nghttp2_submit_response2(session_, id, nva.data(), nva.size(),
                             no_body ? nullptr : &provider);
  } else if (exchange.upstream_failed) {
    nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, id,
                              NGHTTP2_INTERNAL_ERROR);
  } else {
    nghttp2_session_resume_data(session_, id);
  }
  Flush();
}

int H2ServerConnection::OnBeginHeaders(nghttp2_session* session,
                                       const nghttp2_frame* frame,
                                       void* user_data) {
  if (frame->hd.type != NGHTTP2_HEADERS) return 0;
  auto* self = static_cast<H2ServerConnection*>(user_data);
  self->header_block_stream_ = frame->hd.stream_id;
  if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
  auto stream = std::make_unique<Stream>();
  stream->id = frame->hd.stream_id;
  stream->observed.version = "2";
  nghttp2_session_set_stream_user_data(session, stream->id, stream.get());
  self->streams_[stream->id] = std::move(stream);
  return 0;
}

int H2ServerConnection::OnHeader(nghttp2_session* session,
                                 const nghttp2_frame* frame,
                                 const uint8_t* name, std::size_t name_size,
                                 const uint8_t* value, std::size_t value_size,
                                 uint8_t /*flags*/, void* /*user_data*/) {
  if (frame->hd.type != NGHTTP2_HEADERS) return 0;
  auto* stream = static_cast<Stream*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
  if (stream == nullptr) return 0;
  std::string header = ToString(name, name_size);
  std::string text = ToString(value, value_size);
  if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    stream->trailers.emplace_back(std::move(header), std::move(text));
    return 0;
  }
  if (header.starts_with(':')) {
    if (header == ":method") {
      stream->request.method = text;
      stream->observed.method = text;
    } else if (header == ":authority") {
      stream->request.authority = text;
      stream->observed.authority = text;
    } else if (header == ":path") {
      stream->request.path = text;
      stream->observed.target = text;
    }
    stream->observed.pseudo_header_order.push_back(std::move(header));
    return 0;
  }
  stream->observed.header_names.push_back(header);
  stream->observed.headers.emplace_back(header, text);
  stream->request.headers.emplace_back(std::move(header), std::move(text));
  return 0;
}

int H2ServerConnection::OnFrameRecv(nghttp2_session* /*session*/,
                                    const nghttp2_frame* frame,
                                    void* user_data) {
  auto* self = static_cast<H2ServerConnection*>(user_data);
  const bool end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
  switch (frame->hd.type) {
    case NGHTTP2_SETTINGS: {
      if ((frame->hd.flags & NGHTTP2_FLAG_ACK) != 0) break;
      std::vector<std::pair<uint16_t, uint32_t>> settings;
      settings.reserve(frame->settings.niv);
      for (std::size_t i = 0; i < frame->settings.niv; ++i) {
        settings.emplace_back(
            static_cast<uint16_t>(frame->settings.iv[i].settings_id),
            frame->settings.iv[i].value);
      }
      self->fingerprint_.OnSettings(settings);
      break;
    }
    case NGHTTP2_WINDOW_UPDATE:
      self->fingerprint_.OnWindowUpdate(
          static_cast<uint32_t>(frame->hd.stream_id),
          static_cast<uint32_t>(frame->window_update.window_size_increment));
      break;
    case NGHTTP2_PRIORITY:
      self->fingerprint_.OnPriority(
          static_cast<uint32_t>(frame->hd.stream_id),
          frame->priority.pri_spec.exclusive != 0,
          static_cast<uint32_t>(frame->priority.pri_spec.stream_id),
          frame->priority.pri_spec.weight);
      break;
    case NGHTTP2_RST_STREAM:
      GlobalMetrics().h2_client_resets.Inc();
      break;
    case NGHTTP2_HEADERS: {
      if (self->header_block_stream_ == frame->hd.stream_id) {
        self->header_block_stream_ = 0;
      }
      Stream* stream = self->FindStream(frame->hd.stream_id);
      if (stream == nullptr) break;
      if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        self->OnRequestHeaders(*stream, end_stream);
      } else if (stream->exchange) {
        stream->exchange->EndRequest(std::move(stream->trailers));
      }
      break;
    }
    case NGHTTP2_DATA: {
      Stream* stream = self->FindStream(frame->hd.stream_id);
      if (stream != nullptr && stream->exchange && end_stream) {
        stream->exchange->EndRequest();
      }
      break;
    }
    default:
      break;
  }
  return 0;
}

int H2ServerConnection::OnDataChunk(nghttp2_session* session, uint8_t /*flags*/,
                                    int32_t stream_id, const uint8_t* data,
                                    std::size_t size, void* user_data) {
  auto* self = static_cast<H2ServerConnection*>(user_data);
  Stream* stream = self->FindStream(stream_id);
  if (stream == nullptr || !stream->exchange) {
    nghttp2_session_consume(session, stream_id, size);
    return 0;
  }
  stream->body_rate.Received(size);
  stream->exchange->PushRequestBody(std::span(data, size));
  return 0;
}

int H2ServerConnection::OnInvalidFrameRecv(nghttp2_session* /*session*/,
                                           const nghttp2_frame* frame,
                                           int /*error_code*/,
                                           void* user_data) {
  auto* self = static_cast<H2ServerConnection*>(user_data);
  if (frame->hd.type == NGHTTP2_HEADERS &&
      self->header_block_stream_ == frame->hd.stream_id) {
    self->header_block_stream_ = 0;
  }
  return 0;
}

int H2ServerConnection::OnStreamClose(nghttp2_session* /*session*/,
                                      int32_t stream_id,
                                      uint32_t /*error_code*/,
                                      void* user_data) {
  auto* self = static_cast<H2ServerConnection*>(user_data);
  if (self->header_block_stream_ == stream_id) self->header_block_stream_ = 0;
  Stream* stream = self->FindStream(stream_id);
  if (stream == nullptr) return 0;
  if (stream->exchange) {
    const Exchange& exchange = *stream->exchange;
    if (!exchange.response_ended || !exchange.response_body.empty()) {
      stream->exchange->CancelFromClient();
    }
    stream->exchange->wake_client = nullptr;
    stream->exchange->request_consumed = nullptr;
    self->Report(*stream);
  }
  self->streams_.erase(stream_id);
  return 0;
}

nghttp2_ssize H2ServerConnection::ReadResponseData(
    nghttp2_session* session, int32_t stream_id, uint8_t* buffer,
    std::size_t size, uint32_t* data_flags, nghttp2_data_source* source,
    void* /*user_data*/) {
  auto* stream = static_cast<Stream*>(source->ptr);
  Exchange& exchange = *stream->exchange;
  if (exchange.upstream_failed) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  const std::size_t n = exchange.ReadResponseBody(std::span(buffer, size));
  if (exchange.response_ended && exchange.response_body.empty()) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    if (!exchange.response_trailers.empty()) {
      *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      // nghttp2 copies the fields; `trailers` only has to outlive the call.
      const HeaderList trailers =
          FilterResponseHeaders(exchange.response_trailers);
      const std::vector<nghttp2_nv> nva = MakeNva(trailers);
      nghttp2_submit_trailer(session, stream_id, nva.data(), nva.size());
    }
    return static_cast<nghttp2_ssize>(n);
  }
  if (n == 0) return NGHTTP2_ERR_DEFERRED;
  return static_cast<nghttp2_ssize>(n);
}

}  // namespace bot_shield
