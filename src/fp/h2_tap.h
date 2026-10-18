#ifndef BOT_SHIELD_FP_H2_TAP_H_
#define BOT_SHIELD_FP_H2_TAP_H_

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "fp/h2_fingerprint.h"
#include "fp/http_request.h"

struct nghttp2_hd_inflater;

namespace bot_shield {

// Passive HTTP/2 client stream reader. Follows the frame layer, decodes every
// header block (HPACK state must stay in sync) and reports requests. Also
// builds the connection fingerprint in the public Akamai format:
//   SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order
//   e.g. 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
// DATA payloads are skipped without buffering.
class H2Tap {
 public:
  explicit H2Tap(HttpRequestCallback on_request);
  ~H2Tap();

  H2Tap(const H2Tap&) = delete;
  H2Tap& operator=(const H2Tap&) = delete;

  void Feed(std::span<const uint8_t> data);
  bool active() const { return active_; }
  int requests() const { return requests_; }

  // Empty until the first request HEADERS frame has been decoded.
  const std::string& fingerprint() const { return builder_.fingerprint(); }

 private:
  enum class State { kPreface, kFrameHeader, kPayload, kSkip };

  struct FrameHeader {
    uint32_t length = 0;
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
  };

  void StartFrame();
  void ProcessFrame();
  void OnSettings();
  void OnWindowUpdate();
  void OnPriority();
  void OnHeaders();
  void OnContinuation();
  void DecodeHeaderBlock();
  void Stop() { active_ = false; }

  HttpRequestCallback on_request_;
  nghttp2_hd_inflater* inflater_ = nullptr;

  State state_ = State::kPreface;
  std::string buffer_;
  FrameHeader frame_;
  uint32_t skip_remaining_ = 0;

  std::string header_block_;
  uint32_t header_block_stream_ = 0;
  bool expect_continuation_ = false;

  bool settings_seen_ = false;
  bool headers_seen_ = false;
  H2FingerprintBuilder builder_;

  int requests_ = 0;
  bool active_ = true;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_H2_TAP_H_
