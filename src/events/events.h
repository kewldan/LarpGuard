#ifndef BOT_SHIELD_EVENTS_EVENTS_H_
#define BOT_SHIELD_EVENTS_EVENTS_H_

#include <asio/ip/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"

namespace bot_shield {

struct EventSettings {
  // Random per process start; tells connection ids of different runs apart.
  std::string instance;
  // Key for IP hashes. Full addresses never leave the gateway.
  std::string ip_salt;
  // Emit one event per HTTP request (needs the HTTP taps).
  bool requests = true;
};

// What is known about a client connection; filled in as it progresses and
// emitted as a "conn" event when it closes.
struct ConnectionRecord {
  uint64_t id = 0;
  int64_t started_ms = 0;
  std::string listener;
  asio::ip::address peer;
  std::string server_name;
  std::string route;
  std::string reason;
  std::string tls_version;
  std::string alpn_offered;
  std::string alpn;
  std::string ja4;
  std::string ja4_raw;
  std::string tcp_fingerprint;
  std::string ja4t;
  std::string h2_fingerprint;
  // The ClientHello offered ALPN "h2" (or "h3" over QUIC).
  bool offered_h2 = false;
  // QUIC (HTTP/3) connection; transport parameter ids in ClientHello order.
  bool quic = false;
  std::string quic_fp;
  // Initial TTL of the SYN (64, 128, ...); 0 when not captured.
  int tcp_initial_ttl = 0;
  // Round trips, -1 when unknown. The kernel's TCP RTT reaches the nearest
  // TCP stack (a proxy's, if any); the TLS handshake (server flight to the
  // client's Finished) reaches the TLS client itself. TLS 1.3 only: one
  // round trip there.
  int64_t tcp_rtt_us = -1;
  int64_t handshake_us = -1;
  // Autonomous system of the peer (ASN database); 0 when unknown.
  uint32_t asn = 0;
  uint64_t bytes_in = 0;
  uint64_t bytes_out = 0;
  int requests = 0;
};

int64_t UnixMillis();

// "203.0.113.0/24" for IPv4, "2001:db8:1::/48" for IPv6.
std::string IpPrefix(const asio::ip::address& address);

// HMAC-SHA256(salt, address bytes), 16 hex chars.
std::string IpHash(const asio::ip::address& address, std::string_view salt);

// Path without query, with variable segments replaced: numbers -> ":n",
// UUIDs -> ":uuid", long hex -> ":hex", anything over 64 chars -> ":long".
std::string PathGroup(std::string_view target);

std::string ConnectionEventJson(const ConnectionRecord& record,
                                const EventSettings& settings,
                                int64_t ended_ms);

// How a proxied request ended (absent for passively observed requests).
struct RequestOutcome {
  // 0 when no response was produced (client went away first).
  int status = 0;
  int64_t duration_ms = 0;
  uint64_t response_bytes = 0;
  // Answered by the gateway itself.
  bool local = false;
  // Verdict (score < 0: not scored).
  int score = -1;
  std::string bot_class;
  std::vector<std::string> reasons;
  std::string action;
  std::string would_action;
  // Name of the rate limit that refused the request, if any.
  std::string rate_limit;
  std::string request_id;
  // Decoy watermark (action decoy).
  std::string watermark;
  std::vector<float> features;
  double model_score = -1;
  // Hash of the browser probes of a challenge or CAPTCHA (canvas, WebGL,
  // audio, fonts), for clustering.
  std::string client_fp;
  // Host of a verified Web Bot Auth agent.
  std::string signed_agent;
};

std::string RequestEventJson(const ConnectionRecord& record,
                             const HttpRequest& request, int sequence,
                             const EventSettings& settings, int64_t time_ms,
                             const RequestOutcome* outcome = nullptr);

}  // namespace bot_shield

#endif  // BOT_SHIELD_EVENTS_EVENTS_H_
