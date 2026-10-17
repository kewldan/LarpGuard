#ifndef BOT_SHIELD_FP_H1_TAP_H_
#define BOT_SHIELD_FP_H1_TAP_H_

#include <llhttp.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "fp/http_request.h"

namespace bot_shield {

// Passive HTTP/1.x request parser. Feed it the client-to-upstream bytes; it
// reports each request's headers and never alters the stream. It stops at a
// protocol upgrade (WebSocket), a parse error or a limit.
class H1Tap {
 public:
  explicit H1Tap(HttpRequestCallback on_request);

  // llhttp keeps pointers to this object.
  H1Tap(const H1Tap&) = delete;
  H1Tap& operator=(const H1Tap&) = delete;

  void Feed(std::span<const uint8_t> data);
  bool active() const { return active_; }
  int requests() const { return requests_; }

 private:
  static H1Tap& Self(llhttp_t* parser);
  static int OnMessageBegin(llhttp_t* parser);
  static int OnMethod(llhttp_t* parser, const char* at, std::size_t size);
  static int OnUrl(llhttp_t* parser, const char* at, std::size_t size);
  static int OnHeaderField(llhttp_t* parser, const char* at, std::size_t size);
  static int OnHeaderValue(llhttp_t* parser, const char* at, std::size_t size);
  static int OnHeaderValueComplete(llhttp_t* parser);
  static int OnHeadersComplete(llhttp_t* parser);

  // Adds `size` header bytes; false once over the limit.
  bool Account(std::size_t size);

  HttpRequestCallback on_request_;
  llhttp_settings_t settings_{};
  llhttp_t parser_{};
  HttpRequest current_;
  std::string field_;
  std::string value_;
  std::size_t header_bytes_ = 0;
  int requests_ = 0;
  bool active_ = true;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_H1_TAP_H_
