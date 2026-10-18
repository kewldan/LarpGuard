#ifndef BOT_SHIELD_EVENTS_EVENTS_H_
#define BOT_SHIELD_EVENTS_EVENTS_H_

#include <asio/ip/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>

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
};

std::string RequestEventJson(const ConnectionRecord& record,
                             const HttpRequest& request, int sequence,
                             const EventSettings& settings, int64_t time_ms,
                             const RequestOutcome* outcome = nullptr);

}  // namespace bot_shield

#endif  // BOT_SHIELD_EVENTS_EVENTS_H_
