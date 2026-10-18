#ifndef BOT_SHIELD_SERVER_CONNECTION_H_
#define BOT_SHIELD_SERVER_CONNECTION_H_

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl/context.hpp>
#include <string>

#include "admin/decision_log.h"
#include "admin/lists.h"
#include "challenge/challenger.h"
#include "config/config.h"
#include "docker/labels.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "net/classifier.h"
#include "proxy/proxy_hooks.h"
#include "proxy/upstream_pool.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "score/rules.h"
#include "score/scorer.h"
#include "tls/cert_store.h"

namespace bot_shield {

// Everything a connection handler needs. Owned by a worker and outlives all
// coroutines running on that worker's io_context.
struct GatewayContext {
  const Config* config = nullptr;
  const CertStore* certificates = nullptr;
  const Classifier* classifier = nullptr;
  asio::ip::tcp::endpoint upstream_https;
  asio::ip::tcp::endpoint upstream_http;
  // Client-side TLS context for connections to Traefik (per worker).
  asio::ssl::context* upstream_tls = nullptr;
  // Per-worker HTTP/2 connection pool to Traefik.
  UpstreamPool* pool = nullptr;
  ProxySettings proxy_settings;
  // Verdicts (shared, immutable).
  const Scorer* scorer = nullptr;
  const Policy* policy = nullptr;
  const RuleSet* rules = nullptr;
  // Request rate limits and their shared state (all workers).
  const RateLimitSet* rate_limits = nullptr;
  RateLimitStore* rate_limit_store = nullptr;
  // Policies from docker labels; null when Docker is not used.
  const LabelStore* labels = nullptr;
  // JS challenge and clearance tokens; null when not configured.
  const Challenger* challenger = nullptr;
  // Operational allow/block lists and the recent-decision log (admin API).
  const ListStore* lists = nullptr;
  DecisionLog* decisions = nullptr;
  // Per-IP connection limits at accept time (shared).
  ConnectionCounter* connection_counter = nullptr;
  // Analytics events; null when disabled.
  EventSink* events = nullptr;
  const EventSettings* event_settings = nullptr;
};

// Port 443: reads the ClientHello, then terminates TLS or passes the
// connection through to Traefik.
asio::awaitable<void> HandleHttpsConnection(asio::ip::tcp::socket socket,
                                            const GatewayContext& context);

// Port 80: passes the connection through to Traefik (keeps HTTP-01 ACME
// challenges and HTTPS redirects working).
asio::awaitable<void> HandleHttpConnection(asio::ip::tcp::socket socket,
                                           const GatewayContext& context);

std::string FormatEndpoint(const asio::ip::tcp::endpoint& endpoint);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_CONNECTION_H_
