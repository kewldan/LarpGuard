#include "fp/h1_tap.h"

#include <llhttp.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "fp/http_request.h"

namespace bot_shield {
namespace {

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

}  // namespace

H1Tap::H1Tap(HttpRequestCallback on_request)
    : on_request_(std::move(on_request)) {
  llhttp_settings_init(&settings_);
  settings_.on_message_begin = &H1Tap::OnMessageBegin;
  settings_.on_method = &H1Tap::OnMethod;
  settings_.on_url = &H1Tap::OnUrl;
  settings_.on_header_field = &H1Tap::OnHeaderField;
  settings_.on_header_value = &H1Tap::OnHeaderValue;
  settings_.on_header_value_complete = &H1Tap::OnHeaderValueComplete;
  settings_.on_headers_complete = &H1Tap::OnHeadersComplete;
  llhttp_init(&parser_, HTTP_REQUEST, &settings_);
  parser_.data = this;
}

void H1Tap::Feed(std::span<const uint8_t> data) {
  if (!active_ || data.empty()) return;
  const llhttp_errno_t error = llhttp_execute(
      &parser_, reinterpret_cast<const char*>(data.data()), data.size());
  // Stop on errors and on upgrades: after an upgrade the stream is no longer
  // HTTP/1.x.
  if (error != HPE_OK) active_ = false;
}

H1Tap& H1Tap::Self(llhttp_t* parser) {
  return *static_cast<H1Tap*>(parser->data);
}

bool H1Tap::Account(std::size_t size) {
  header_bytes_ += size;
  return header_bytes_ <= kMaxTapHeaderBytes;
}

int H1Tap::OnMessageBegin(llhttp_t* parser) {
  H1Tap& self = Self(parser);
  self.current_ = HttpRequest{};
  self.field_.clear();
  self.value_.clear();
  self.header_bytes_ = 0;
  return 0;
}

int H1Tap::OnMethod(llhttp_t* parser, const char* at, std::size_t size) {
  H1Tap& self = Self(parser);
  self.current_.method.append(at, size);
  return self.Account(size) ? 0 : -1;
}

int H1Tap::OnUrl(llhttp_t* parser, const char* at, std::size_t size) {
  H1Tap& self = Self(parser);
  self.current_.target.append(at, size);
  return self.Account(size) ? 0 : -1;
}

int H1Tap::OnHeaderField(llhttp_t* parser, const char* at, std::size_t size) {
  H1Tap& self = Self(parser);
  self.field_.append(at, size);
  return self.Account(size) ? 0 : -1;
}

int H1Tap::OnHeaderValue(llhttp_t* parser, const char* at, std::size_t size) {
  H1Tap& self = Self(parser);
  self.value_.append(at, size);
  return self.Account(size) ? 0 : -1;
}

int H1Tap::OnHeaderValueComplete(llhttp_t* parser) {
  H1Tap& self = Self(parser);
  std::string lowercase = Lowercase(self.field_);
  if (lowercase == "host" && self.current_.authority.empty()) {
    self.current_.authority = self.value_;
  }
  self.current_.header_names.push_back(std::move(self.field_));
  self.current_.headers.emplace_back(std::move(lowercase),
                                     std::move(self.value_));
  self.field_.clear();
  self.value_.clear();
  return 0;
}

int H1Tap::OnHeadersComplete(llhttp_t* parser) {
  H1Tap& self = Self(parser);
  self.current_.version =
      std::format("{}.{}", parser->http_major, parser->http_minor);
  ++self.requests_;
  if (self.on_request_) self.on_request_(std::move(self.current_));
  self.current_ = HttpRequest{};
  // Returning an error stops parsing; past the limit we no longer care.
  return self.requests_ >= kMaxTapRequests ? -1 : 0;
}

}  // namespace bot_shield
