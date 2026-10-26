#ifndef BOT_SHIELD_SERVER_CONNECTION_H_
#define BOT_SHIELD_SERVER_CONNECTION_H_

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ssl/context.hpp>
#include <memory>
#include <string>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "behavior/behavior.h"
#include "challenge/captcha.h"
#include "challenge/challenger.h"
#include "config/config.h"
#include "crawler/ranges.h"
#include "crawler/verifier.h"
#include "crawler/web_bot_auth.h"
#include "docker/labels.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "model/gbdt.h"
#include "net/asn.h"
#include "net/classifier.h"
#include "net/geoip.h"
#include "net/threat_lists.h"
#include "proxy/proxy_hooks.h"
#include "proxy/upstream_pool.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "score/rule_samples.h"
#include "score/rules.h"
#include "score/scorer.h"
#include "server/verdicts.h"
#include "tls/cert_store.h"
#include "tls/client_hello.h"
#include "xdp/xdp_filter.h"

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
  // Library, scoring, policy, rules, limits, model: one snapshot per
  // request (replaced on reload).
  const VerdictStore* verdicts = nullptr;
  // Rate limit state (all workers; survives reloads).
  RateLimitStore* rate_limit_store = nullptr;
  // Policies from docker labels; null when Docker is not used.
  const LabelStore* labels = nullptr;
  // Reverse DNS checks of search crawlers; null when disabled.
  CrawlerVerifier* crawler_verifier = nullptr;
  // Behaviour signals and honeypot marks; null when disabled.
  BehaviorStore* behavior = nullptr;
  // JS challenge and clearance tokens; null when not configured.
  const Challenger* challenger = nullptr;
  // CAPTCHA (captcha.provider); null when off.
  Captcha* captcha = nullptr;
  // Published crawler IP ranges; null when crawlers.ip_ranges is off.
  const CrawlerRangeStore* crawler_ranges = nullptr;
  // Web Bot Auth signatures; null when off.
  WebBotAuthVerifier* web_bot_auth = nullptr;
  // IP -> AS database; null when asn.url is "".
  const AsnStore* asn = nullptr;
  // Public IP reputation lists (threat_lists); null when none enabled.
  const ThreatListStore* threat_lists = nullptr;
  // IP -> country (geoip.url); null when off.
  const GeoStore* geoip = nullptr;
  // Honeypot hits dropped in XDP (xdp.block_honeypot); null when off.
  XdpAutoBlocks* xdp_blocks = nullptr;
  // Operational allow/block lists and the recent-decision log (admin API).
  const ListStore* lists = nullptr;
  DecisionLog* decisions = nullptr;
  // Under-attack mode (admin API and attack.auto_rps); shared.
  AttackMode* attack = nullptr;
  // Recent requests for testing draft rules live; null without the admin
  // API.
  RuleSampleRing* rule_samples = nullptr;
  // Per-IP connection limits at accept time (shared).
  ConnectionCounter* connection_counter = nullptr;
  // Per-IP connections still before their first request headers (shared).
  ConnectionCounter* pending_counter = nullptr;
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

// Verdicts and events of one QUIC (HTTP/3) connection: the same observer
// as for TCP, behind an interface for src/quic.
class QuicObserver {
 public:
  virtual ~QuicObserver() = default;
  // Hooks for the HTTP/3 session; valid while the observer lives.
  virtual ProxyHooks Hooks() = 0;
};

// `transport_params` is the QUIC transport parameter fingerprint.
std::unique_ptr<QuicObserver> MakeQuicObserver(
    const GatewayContext& context, const asio::ip::udp::endpoint& peer,
    const asio::ip::udp::endpoint& local, const ClientHello& hello,
    std::string transport_params, const asio::any_io_executor& executor);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_CONNECTION_H_
