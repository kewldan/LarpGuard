#include "proxy/h2_upstream.h"

#include <nghttp2/nghttp2.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "proxy/exchange.h"
#include "proxy/h2_connection.h"
#include "proxy/http_message.h"
#include "proxy/transport.h"

namespace bot_shield {
namespace {

constexpr uint32_t kInitialWindowSize = 1 << 20;
constexpr int32_t kConnectionWindowSize = 1 << 24;

std::string ToString(const uint8_t* data, std::size_t size) {
  return {reinterpret_cast<const char*>(data), size};
}

}  // namespace

std::shared_ptr<H2UpstreamConnection> H2UpstreamConnection::Create(
    std::unique_ptr<Transport> transport,
    std::chrono::milliseconds idle_timeout) {
  return std::shared_ptr<H2UpstreamConnection>(
      new H2UpstreamConnection(std::move(transport), idle_timeout));
}

H2UpstreamConnection::H2UpstreamConnection(
    std::unique_ptr<Transport> transport,
    std::chrono::milliseconds idle_timeout)
    : H2Connection(std::move(transport), idle_timeout) {
  nghttp2_session_callbacks* callbacks = nullptr;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, &OnHeader);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &OnFrameRecv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                            &OnDataChunk);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                         &OnStreamClose);
  nghttp2_option* option = nullptr;
  nghttp2_option_new(&option);
  // Window updates follow what the client actually received.
  nghttp2_option_set_no_auto_window_update(option, 1);
  nghttp2_session_client_new2(&session_, callbacks, this, option);
  nghttp2_option_del(option);
  nghttp2_session_callbacks_del(callbacks);
}

void H2UpstreamConnection::Start() {
  const std::array<nghttp2_settings_entry, 2> settings = {{
      {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, kInitialWindowSize},
  }};
  nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings.data(),
                          settings.size());
  nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0,
                                        kConnectionWindowSize);
  StartIo();
}

H2UpstreamConnection::Stream* H2UpstreamConnection::FindStream(int32_t id) {
  const auto it = streams_.find(id);
  return it == streams_.end() ? nullptr : it->second.get();
}

void H2UpstreamConnection::Submit(const std::shared_ptr<Exchange>& exchange) {
  if (!usable()) {
    exchange->FailUpstream();
    return;
  }
  const ProxyRequest& request = exchange->request;
  HeaderList headers = {{":method", request.method},
                        {":scheme", request.scheme},
                        {":authority", request.authority},
                        {":path", request.path}};
  headers.insert(headers.end(), request.headers.begin(), request.headers.end());
  const std::vector<nghttp2_nv> nva = MakeNva(headers);

  auto stream = std::make_unique<Stream>();
  stream->exchange = exchange;
  const bool no_body = exchange->request_ended &&
                       exchange->request_body.empty() &&
                       exchange->request_trailers.empty();
  nghttp2_data_provider2 provider{};
  provider.source.ptr = stream.get();
  provider.read_callback = &ReadRequestData;
  const int32_t id =
      nghttp2_submit_request2(session_, nullptr, nva.data(), nva.size(),
                              no_body ? nullptr : &provider, stream.get());
  if (id < 0) {
    exchange->FailUpstream();
    return;
  }
  stream->id = id;
  streams_[id] = std::move(stream);

  std::weak_ptr<H2Connection> weak = weak_from_this();
  exchange->wake_upstream = [weak, id] {
    auto self = weak.lock();
    if (!self || self->closed()) return;
    auto* upstream = static_cast<H2UpstreamConnection*>(self.get());
    if (upstream->FindStream(id) == nullptr) return;
    nghttp2_session_resume_data(upstream->session_, id);
    upstream->Flush();
  };
  exchange->response_consumed = [weak, id](std::size_t size) {
    auto self = weak.lock();
    if (!self || self->closed()) return;
    auto* upstream = static_cast<H2UpstreamConnection*>(self.get());
    nghttp2_session_consume(upstream->session_, id, size);
    upstream->Flush();
  };
  exchange->cancel_upstream = [weak, id] {
    auto self = weak.lock();
    if (!self || self->closed()) return;
    auto* upstream = static_cast<H2UpstreamConnection*>(self.get());
    Stream* stream = upstream->FindStream(id);
    if (stream == nullptr) return;
    stream->exchange.reset();
    nghttp2_submit_rst_stream(upstream->session_, NGHTTP2_FLAG_NONE, id,
                              NGHTTP2_CANCEL);
    upstream->Flush();
  };
  Flush();
}

void H2UpstreamConnection::OnClosed() {
  for (auto& [id, stream] : streams_) {
    if (stream->exchange) stream->exchange->FailUpstream();
  }
  streams_.clear();
}

int H2UpstreamConnection::OnHeader(nghttp2_session* /*session*/,
                                   const nghttp2_frame* frame,
                                   const uint8_t* name, std::size_t name_size,
                                   const uint8_t* value, std::size_t value_size,
                                   uint8_t /*flags*/, void* user_data) {
  if (frame->hd.type != NGHTTP2_HEADERS) return 0;
  auto* self = static_cast<H2UpstreamConnection*>(user_data);
  Stream* stream = self->FindStream(frame->hd.stream_id);
  if (stream == nullptr) return 0;
  std::string header = ToString(name, name_size);
  std::string text = ToString(value, value_size);
  if (frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
      stream->response.status >= 200) {
    stream->trailers.emplace_back(std::move(header), std::move(text));
    return 0;
  }
  if (header == ":status") {
    int status = 0;
    std::from_chars(text.data(), text.data() + text.size(), status);
    stream->response.status = status;
    return 0;
  }
  stream->response.headers.emplace_back(std::move(header), std::move(text));
  return 0;
}

int H2UpstreamConnection::OnFrameRecv(nghttp2_session* /*session*/,
                                      const nghttp2_frame* frame,
                                      void* user_data) {
  auto* self = static_cast<H2UpstreamConnection*>(user_data);
  const bool end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
  switch (frame->hd.type) {
    case NGHTTP2_GOAWAY:
      self->goaway_ = true;
      break;
    case NGHTTP2_HEADERS: {
      Stream* stream = self->FindStream(frame->hd.stream_id);
      if (stream == nullptr || !stream->exchange) break;
      Exchange& exchange = *stream->exchange;
      if (!exchange.response_started) {
        if (stream->response.status < 200) {
          // Interim (1xx) response: wait for the final one.
          stream->response = ProxyResponse{};
          break;
        }
        exchange.SetResponse(std::move(stream->response));
        if (end_stream) exchange.EndResponse();
      } else {
        exchange.EndResponse(std::move(stream->trailers));
      }
      break;
    }
    case NGHTTP2_DATA: {
      Stream* stream = self->FindStream(frame->hd.stream_id);
      if (stream != nullptr && stream->exchange && end_stream) {
        stream->exchange->EndResponse();
      }
      break;
    }
    default:
      break;
  }
  return 0;
}

int H2UpstreamConnection::OnDataChunk(nghttp2_session* session,
                                      uint8_t /*flags*/, int32_t stream_id,
                                      const uint8_t* data, std::size_t size,
                                      void* user_data) {
  auto* self = static_cast<H2UpstreamConnection*>(user_data);
  Stream* stream = self->FindStream(stream_id);
  if (stream == nullptr || !stream->exchange || stream->exchange->local) {
    nghttp2_session_consume(session, stream_id, size);
    return 0;
  }
  stream->exchange->PushResponseBody(std::span(data, size));
  return 0;
}

int H2UpstreamConnection::OnStreamClose(nghttp2_session* /*session*/,
                                        int32_t stream_id,
                                        uint32_t /*error_code*/,
                                        void* user_data) {
  auto* self = static_cast<H2UpstreamConnection*>(user_data);
  Stream* stream = self->FindStream(stream_id);
  if (stream == nullptr) return 0;
  if (stream->exchange) {
    if (!stream->exchange->response_ended) stream->exchange->FailUpstream();
    stream->exchange->wake_upstream = nullptr;
    stream->exchange->response_consumed = nullptr;
    stream->exchange->cancel_upstream = nullptr;
  }
  self->streams_.erase(stream_id);
  return 0;
}

nghttp2_ssize H2UpstreamConnection::ReadRequestData(
    nghttp2_session* session, int32_t stream_id, uint8_t* buffer,
    std::size_t size, uint32_t* data_flags, nghttp2_data_source* source,
    void* /*user_data*/) {
  auto* stream = static_cast<Stream*>(source->ptr);
  if (!stream->exchange) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  Exchange& exchange = *stream->exchange;
  const std::size_t n = exchange.ReadRequestBody(std::span(buffer, size));
  if (exchange.request_ended && exchange.request_body.empty()) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    if (!exchange.request_trailers.empty()) {
      *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      const HeaderList trailers =
          FilterRequestHeaders(exchange.request_trailers);
      const std::vector<nghttp2_nv> nva = MakeNva(trailers);
      nghttp2_submit_trailer(session, stream_id, nva.data(), nva.size());
    }
    return static_cast<nghttp2_ssize>(n);
  }
  if (n == 0) return NGHTTP2_ERR_DEFERRED;
  return static_cast<nghttp2_ssize>(n);
}

}  // namespace bot_shield
