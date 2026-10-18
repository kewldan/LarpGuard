#include "fp/h2_tap.h"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fp/http_request.h"

namespace bot_shield {
namespace {

constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kFrameHeaderSize = 9;

constexpr uint8_t kFrameHeaders = 0x1;
constexpr uint8_t kFramePriority = 0x2;
constexpr uint8_t kFrameSettings = 0x4;
constexpr uint8_t kFrameWindowUpdate = 0x8;
constexpr uint8_t kFrameContinuation = 0x9;

constexpr uint8_t kFlagAck = 0x1;
constexpr uint8_t kFlagEndHeaders = 0x4;
constexpr uint8_t kFlagPadded = 0x8;
constexpr uint8_t kFlagPriority = 0x20;

uint32_t ReadU32(std::string_view data, std::size_t offset) {
  return (uint32_t{static_cast<uint8_t>(data[offset])} << 24) |
         (uint32_t{static_cast<uint8_t>(data[offset + 1])} << 16) |
         (uint32_t{static_cast<uint8_t>(data[offset + 2])} << 8) |
         uint32_t{static_cast<uint8_t>(data[offset + 3])};
}

uint16_t ReadU16(std::string_view data, std::size_t offset) {
  return static_cast<uint16_t>(
      (unsigned{static_cast<uint8_t>(data[offset])} << 8) |
      static_cast<uint8_t>(data[offset + 1]));
}

bool IsBufferedFrame(uint8_t type) {
  return type == kFrameHeaders || type == kFrameContinuation ||
         type == kFrameSettings || type == kFrameWindowUpdate ||
         type == kFramePriority;
}

}  // namespace

H2Tap::H2Tap(HttpRequestCallback on_request)
    : on_request_(std::move(on_request)) {
  if (nghttp2_hd_inflate_new(&inflater_) != 0) {
    inflater_ = nullptr;
    active_ = false;
  }
}

H2Tap::~H2Tap() {
  if (inflater_ != nullptr) nghttp2_hd_inflate_del(inflater_);
}

void H2Tap::Feed(std::span<const uint8_t> data) {
  std::string_view input(reinterpret_cast<const char*>(data.data()),
                         data.size());
  while (active_ && !input.empty()) {
    switch (state_) {
      case State::kPreface: {
        const std::size_t take =
            std::min(kPreface.size() - buffer_.size(), input.size());
        buffer_.append(input.substr(0, take));
        input.remove_prefix(take);
        if (buffer_.size() < kPreface.size()) break;
        if (buffer_ != kPreface) {
          Stop();
          break;
        }
        buffer_.clear();
        state_ = State::kFrameHeader;
        break;
      }
      case State::kFrameHeader: {
        const std::size_t take =
            std::min(kFrameHeaderSize - buffer_.size(), input.size());
        buffer_.append(input.substr(0, take));
        input.remove_prefix(take);
        if (buffer_.size() == kFrameHeaderSize) StartFrame();
        break;
      }
      case State::kPayload: {
        const std::size_t take =
            std::min(frame_.length - buffer_.size(), input.size());
        buffer_.append(input.substr(0, take));
        input.remove_prefix(take);
        if (buffer_.size() == frame_.length) {
          ProcessFrame();
          buffer_.clear();
          state_ = State::kFrameHeader;
        }
        break;
      }
      case State::kSkip: {
        const auto take = static_cast<uint32_t>(
            std::min<std::size_t>(skip_remaining_, input.size()));
        input.remove_prefix(take);
        skip_remaining_ -= take;
        if (skip_remaining_ == 0) state_ = State::kFrameHeader;
        break;
      }
    }
  }
}

void H2Tap::StartFrame() {
  frame_.length = (uint32_t{static_cast<uint8_t>(buffer_[0])} << 16) |
                  (uint32_t{static_cast<uint8_t>(buffer_[1])} << 8) |
                  uint32_t{static_cast<uint8_t>(buffer_[2])};
  frame_.type = static_cast<uint8_t>(buffer_[3]);
  frame_.flags = static_cast<uint8_t>(buffer_[4]);
  frame_.stream_id = ReadU32(buffer_, 5) & 0x7FFFFFFF;
  buffer_.clear();

  // A header block must continue with CONTINUATION frames only.
  if (expect_continuation_ && frame_.type != kFrameContinuation) {
    Stop();
    return;
  }
  if (!IsBufferedFrame(frame_.type)) {
    skip_remaining_ = frame_.length;
    state_ = frame_.length == 0 ? State::kFrameHeader : State::kSkip;
    return;
  }
  if (frame_.length > kMaxTapHeaderBytes) {
    Stop();
    return;
  }
  if (frame_.length == 0) {
    ProcessFrame();
    state_ = State::kFrameHeader;
    return;
  }
  state_ = State::kPayload;
}

void H2Tap::ProcessFrame() {
  switch (frame_.type) {
    case kFrameSettings:
      OnSettings();
      break;
    case kFrameWindowUpdate:
      OnWindowUpdate();
      break;
    case kFramePriority:
      OnPriority();
      break;
    case kFrameHeaders:
      OnHeaders();
      break;
    case kFrameContinuation:
      OnContinuation();
      break;
    default:
      break;
  }
}

void H2Tap::OnSettings() {
  if ((frame_.flags & kFlagAck) != 0 || settings_seen_) return;
  settings_seen_ = true;
  if (buffer_.size() % 6 != 0) {
    Stop();
    return;
  }
  std::vector<std::pair<uint16_t, uint32_t>> settings;
  for (std::size_t i = 0; i < buffer_.size(); i += 6) {
    settings.emplace_back(ReadU16(buffer_, i), ReadU32(buffer_, i + 2));
  }
  builder_.OnSettings(settings);
}

void H2Tap::OnWindowUpdate() {
  if (buffer_.size() != 4) return;
  builder_.OnWindowUpdate(frame_.stream_id, ReadU32(buffer_, 0) & 0x7FFFFFFF);
}

void H2Tap::OnPriority() {
  if (buffer_.size() != 5) return;
  const uint32_t dependency = ReadU32(buffer_, 0);
  builder_.OnPriority(frame_.stream_id, (dependency & 0x80000000) != 0,
                      dependency & 0x7FFFFFFF,
                      static_cast<uint8_t>(buffer_[4]) + 1);
}

void H2Tap::OnHeaders() {
  std::string_view payload = buffer_;
  std::size_t padding = 0;
  if ((frame_.flags & kFlagPadded) != 0) {
    if (payload.empty()) return Stop();
    padding = static_cast<uint8_t>(payload[0]);
    payload.remove_prefix(1);
  }
  if ((frame_.flags & kFlagPriority) != 0) {
    if (payload.size() < 5) return Stop();
    payload.remove_prefix(5);
  }
  if (padding > payload.size()) return Stop();
  payload.remove_suffix(padding);

  header_block_.assign(payload);
  header_block_stream_ = frame_.stream_id;
  if ((frame_.flags & kFlagEndHeaders) != 0) {
    DecodeHeaderBlock();
  } else {
    expect_continuation_ = true;
  }
}

void H2Tap::OnContinuation() {
  if (!expect_continuation_ || frame_.stream_id != header_block_stream_) {
    return Stop();
  }
  header_block_ += buffer_;
  if (header_block_.size() > kMaxTapHeaderBytes) return Stop();
  if ((frame_.flags & kFlagEndHeaders) != 0) {
    expect_continuation_ = false;
    DecodeHeaderBlock();
  }
}

void H2Tap::DecodeHeaderBlock() {
  HttpRequest request;
  request.version = "2";
  const auto* in = reinterpret_cast<const uint8_t*>(header_block_.data());
  std::size_t remaining = header_block_.size();
  while (true) {
    nghttp2_nv nv{};
    int flags = 0;
    const nghttp2_ssize consumed =
        nghttp2_hd_inflate_hd3(inflater_, &nv, &flags, in, remaining, 1);
    if (consumed < 0) return Stop();
    in += consumed;
    remaining -= static_cast<std::size_t>(consumed);
    if ((flags & NGHTTP2_HD_INFLATE_EMIT) != 0) {
      std::string name(reinterpret_cast<const char*>(nv.name), nv.namelen);
      std::string value(reinterpret_cast<const char*>(nv.value), nv.valuelen);
      if (name.starts_with(':')) {
        if (name == ":method") request.method = value;
        if (name == ":authority") request.authority = value;
        if (name == ":path") request.target = value;
        request.pseudo_header_order.push_back(name);
      } else {
        request.header_names.push_back(name);
        request.headers.emplace_back(std::move(name), std::move(value));
      }
    }
    if ((flags & NGHTTP2_HD_INFLATE_FINAL) != 0) {
      nghttp2_hd_inflate_end_headers(inflater_);
      break;
    }
    if (consumed == 0 && remaining == 0) break;
  }
  header_block_.clear();

  // Trailers carry no :method; they only keep the HPACK table in sync.
  if (request.method.empty()) return;

  if (!headers_seen_) {
    headers_seen_ = true;
    builder_.OnFirstRequest(request.pseudo_header_order);
  }
  ++requests_;
  if (on_request_) on_request_(std::move(request));
  if (requests_ >= kMaxTapRequests) Stop();
}

}  // namespace bot_shield
