#include "proxy/exchange.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "proxy/http_message.h"

namespace bot_shield {

void BodyQueue::Push(std::span<const uint8_t> data) {
  if (data.empty()) return;
  chunks_.emplace_back(reinterpret_cast<const char*>(data.data()), data.size());
  size_ += data.size();
}

std::size_t BodyQueue::Read(std::span<uint8_t> out) {
  std::size_t copied = 0;
  while (copied < out.size() && !chunks_.empty()) {
    const std::string& chunk = chunks_.front();
    const std::size_t n = std::min(out.size() - copied, chunk.size() - offset_);
    std::memcpy(out.data() + copied, chunk.data() + offset_, n);
    copied += n;
    offset_ += n;
    if (offset_ == chunk.size()) {
      chunks_.pop_front();
      offset_ = 0;
    }
  }
  size_ -= copied;
  return copied;
}

void Exchange::PushRequestBody(std::span<const uint8_t> data) {
  if (local) {
    // Nobody will read it; give the flow-control credit back at once.
    if (request_consumed) request_consumed(data.size());
    return;
  }
  request_body.Push(data);
  if (wake_upstream) wake_upstream();
}

void Exchange::EndRequest(HeaderList trailers) {
  request_ended = true;
  request_trailers = std::move(trailers);
  if (wake_upstream) wake_upstream();
}

std::size_t Exchange::ReadResponseBody(std::span<uint8_t> out) {
  const std::size_t n = response_body.Read(out);
  response_bytes += n;
  if (n > 0 && response_consumed) response_consumed(n);
  return n;
}

void Exchange::CancelFromClient() {
  if (client_cancelled) return;
  client_cancelled = true;
  wake_client = nullptr;
  request_consumed = nullptr;
  if (cancel_upstream) cancel_upstream();
}

void Exchange::RespondLocally(int status, std::string_view body,
                              const HeaderList& extra_headers,
                              std::string_view content_type) {
  local = true;
  response = LocalResponse(status, body.size());
  response.headers[0].second = content_type;  // LocalResponse: content-type.
  response.headers.insert(response.headers.end(), extra_headers.begin(),
                          extra_headers.end());
  response_started = true;
  response_body = BodyQueue{};
  response_body.Push(
      std::span(reinterpret_cast<const uint8_t*>(body.data()), body.size()));
  response_ended = true;
  upstream_failed = false;
  if (cancel_upstream) cancel_upstream();
  if (wake_client) wake_client();
}

void Exchange::StartLocalStream(int status, std::size_t content_length,
                                const HeaderList& extra_headers,
                                std::string_view content_type) {
  local = true;
  response = LocalResponse(status, content_length);
  response.headers[0].second = content_type;  // LocalResponse: content-type.
  response.headers.insert(response.headers.end(), extra_headers.begin(),
                          extra_headers.end());
  response_started = true;
  response_body = BodyQueue{};
  response_ended = false;
  upstream_failed = false;
  if (cancel_upstream) cancel_upstream();
  if (wake_client) wake_client();
}

void Exchange::PushLocalBody(std::string_view data) {
  response_body.Push(
      std::span(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
  if (wake_client) wake_client();
}

void Exchange::EndLocalBody() {
  response_ended = true;
  if (wake_client) wake_client();
}

std::size_t Exchange::ReadRequestBody(std::span<uint8_t> out) {
  const std::size_t n = request_body.Read(out);
  if (n > 0 && request_consumed) request_consumed(n);
  return n;
}

void Exchange::SetResponse(ProxyResponse new_response) {
  if (local) return;
  response = std::move(new_response);
  response_started = true;
  if (wake_client) wake_client();
}

void Exchange::PushResponseBody(std::span<const uint8_t> data) {
  if (local) return;
  response_body.Push(data);
  if (wake_client) wake_client();
}

void Exchange::EndResponse(HeaderList trailers) {
  if (local) return;
  response_ended = true;
  response_trailers = std::move(trailers);
  if (wake_client) wake_client();
}

void Exchange::FailUpstream() {
  if (local || response_ended) return;
  upstream_failed = true;
  if (wake_client) wake_client();
}

}  // namespace bot_shield
