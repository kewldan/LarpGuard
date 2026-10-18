#ifndef BOT_SHIELD_PROXY_PROXY_HOOKS_H_
#define BOT_SHIELD_PROXY_PROXY_HOOKS_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>

#include "proxy/exchange.h"

namespace bot_shield {

// Callbacks from a client-facing session to its owner (the connection
// handler). They run on the worker thread; the session clears them once the
// owner has stopped listening.
struct ProxyHooks {
  // Request headers are complete and forwarding headers added. The owner may
  // add headers to `exchange.request` or answer with RespondLocally().
  std::function<void(Exchange& exchange)> on_request;
  // The exchange finished (response sent, failed or cancelled).
  std::function<void(const Exchange& exchange)> on_done;
  // Raw bytes read from / written to the client (after TLS).
  std::function<void(std::span<const uint8_t> data)> on_client_bytes;
  std::function<void(std::size_t size)> on_bytes_to_client;
};

struct ProxySettings {
  std::chrono::milliseconds idle_timeout{300000};
  // The first request's headers must be complete this long after the
  // connection starts; later ones this long after their first byte
  // (HTTP/1.1) or HEADERS frame (HTTP/2).
  std::chrono::milliseconds request_headers_timeout{10000};
  // Then HTTP/1.1 answers with "Connection: close" and HTTP/2 sends GOAWAY.
  std::size_t max_requests_per_connection = 1000;
  // Alt-Svc sent with every response (HTTP/3 advertisement); empty: none.
  // Alt-Svc from Traefik is always dropped: it would point clients past the
  // gateway (ADR-011).
  std::string alt_svc;
  // Request body buffered per exchange before the client is throttled.
  std::size_t max_buffered_body = std::size_t{1} << 20;
};

int64_t SteadyMillis();

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_PROXY_HOOKS_H_
