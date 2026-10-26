#ifndef BOT_SHIELD_PROXY_EXCHANGE_H_
#define BOT_SHIELD_PROXY_EXCHANGE_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"
#include "proxy/http_message.h"

namespace bot_shield {

// FIFO of body bytes between the two sides of an exchange.
class BodyQueue {
 public:
  void Push(std::span<const uint8_t> data);
  // Moves up to out.size() bytes into `out`; returns how many.
  std::size_t Read(std::span<uint8_t> out);
  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

 private:
  std::deque<std::string> chunks_;
  std::size_t offset_ = 0;  // Into chunks_.front().
  std::size_t size_ = 0;
};

// One request/response pair travelling between a client-facing session
// (HTTP/1.1 or HTTP/2) and an upstream HTTP/2 stream to Traefik.
//
// Each side fills its half and wakes the other through hooks. Body bytes
// are reported back as "consumed" once the other side has taken them; the
// HTTP/2 sessions turn that into WINDOW_UPDATEs, so a slow side throttles a
// fast one instead of growing buffers. Everything runs on one worker thread.
class Exchange : public std::enable_shared_from_this<Exchange> {
 public:
  // --- Called by the client side -------------------------------------------
  void PushRequestBody(std::span<const uint8_t> data);
  void EndRequest(HeaderList trailers = {});
  // Moves response body bytes out; reports them as consumed upstream.
  std::size_t ReadResponseBody(std::span<uint8_t> out);
  // The client stream or connection is gone: stop the upstream stream.
  void CancelFromClient();
  // Answers without Traefik (errors, block pages, 429s); `extra_headers`
  // are added to the generated response.
  void RespondLocally(
      int status, std::string_view body, const HeaderList& extra_headers = {},
      std::string_view content_type = "text/plain; charset=utf-8");
  // A gateway-made response whose body follows later (tarpit): the head
  // goes out now, PushLocalBody adds bytes, EndLocalBody finishes.
  void StartLocalStream(int status, std::size_t content_length,
                        const HeaderList& extra_headers,
                        std::string_view content_type);
  void PushLocalBody(std::string_view data);
  void EndLocalBody();
  // The gateway answers, but later (a CAPTCHA verified by its provider):
  // nothing goes to Traefik and the client waits for RespondLocally().
  void DeferLocalResponse();

  // Drops the unread response body, giving its bytes back to the upstream
  // flow-control window (they were received but will never be read).
  void DiscardResponseBody();

  // --- Called by the upstream side -----------------------------------------
  std::size_t ReadRequestBody(std::span<uint8_t> out);
  // `ended`: the response has no body or trailers (HEADERS with
  // END_STREAM, e.g. a gRPC trailers-only response); the client side then
  // ends its stream with the headers too.
  void SetResponse(ProxyResponse response, bool ended = false);
  void PushResponseBody(std::span<const uint8_t> data);
  void EndResponse(HeaderList trailers = {});
  // The upstream stream or connection failed. Before the response started the
  // client side answers 502, afterwards it aborts the client stream.
  void FailUpstream();

  // --- State ---------------------------------------------------------------
  ProxyRequest request;
  BodyQueue request_body;
  bool request_ended = false;
  HeaderList request_trailers;

  ProxyResponse response;
  bool response_started = false;
  BodyQueue response_body;
  bool response_ended = false;
  HeaderList response_trailers;
  bool upstream_failed = false;
  bool client_cancelled = false;
  // Answered by the gateway; never sent to Traefik.
  bool local = false;

  // What the client sent, for fingerprints and events.
  HttpRequest observed;
  // Akamai-format fingerprint of the client's HTTP/2 connection, if any.
  std::string h2_fingerprint;
  // Verdict set by the connection owner (score < 0: not scored).
  int score = -1;
  std::string bot_class;
  std::vector<std::string> reasons;
  std::string action;
  std::string would_action;
  // Rate limit that refused the request, if any.
  std::string rate_limit;
  // "<instance>-<connection>-<sequence>"; also sent as X-Bot-Request-Id.
  std::string request_id;
  // Behaviour store key of the client (empty: not tracked).
  std::string behavior_client;
  // Token embedded in a decoy answer, to recognize the data later.
  std::string watermark;
  // Model feature vector (empty: not logged) and probability (< 0: none).
  std::vector<float> features;
  double model_score = -1;
  // Hash of the browser probes (challenge or CAPTCHA answers).
  std::string client_fp;
  // Host of a verified Web Bot Auth agent.
  std::string signed_agent;
  // How a claimed crawler or a signed agent was checked, step by step
  // ("claim:googlebot", "ranges:outside", "rdns:verified:googlebot.com",
  // "result:verified"); empty when nothing was claimed or signed.
  std::vector<std::string> crawler_check;
  // Session of a valid clearance token (16 hex digits of its hash).
  std::string session;
  std::string mode;
  int64_t started_ms = 0;
  uint64_t response_bytes = 0;

  // --- Hooks ---------------------------------------------------------------
  // Set by the upstream side.
  std::function<void()> wake_upstream;
  std::function<void(std::size_t)> response_consumed;
  std::function<void()> cancel_upstream;
  // Set by the client side.
  std::function<void()> wake_client;
  std::function<void(std::size_t)> request_consumed;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_EXCHANGE_H_
