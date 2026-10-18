#ifndef BOT_SHIELD_COMMON_METRICS_H_
#define BOT_SHIELD_COMMON_METRICS_H_

#include <atomic>
#include <cstdint>
#include <string>

namespace bot_shield {

struct Counter {
  void Inc(uint64_t n = 1) { value.fetch_add(n, std::memory_order_relaxed); }
  uint64_t Get() const { return value.load(std::memory_order_relaxed); }

  std::atomic<uint64_t> value{0};
};

struct Gauge {
  void Add(int64_t n) { value.fetch_add(n, std::memory_order_relaxed); }
  void Set(int64_t n) { value.store(n, std::memory_order_relaxed); }
  int64_t Get() const { return value.load(std::memory_order_relaxed); }

  std::atomic<int64_t> value{0};
};

// Process-wide counters exposed in the Prometheus text format.
struct Metrics {
  std::string RenderPrometheus() const;

  Counter connections_https;
  Counter connections_http;
  Gauge connections_active;
  Counter rejected_connection_limit;
  Counter rejected_not_tls;
  Counter rejected_invalid_hello;
  Counter client_hello_timeouts;

  Counter route_terminate;
  Counter route_passthrough_acme_tls_alpn;
  Counter route_passthrough_no_server_name;
  Counter route_passthrough_policy;
  Counter route_passthrough_no_certificate;
  Counter route_passthrough_not_tls;

  Counter tls_handshake_failures_client;
  Counter tls_handshake_failures_upstream;
  Counter upstream_connect_failures;
  Counter upstream_connections_opened;
  Counter proxied_requests;
  Counter local_responses;
  Counter websocket_tunnels;
  Counter verdicts_human;
  Counter verdicts_suspicious;
  Counter verdicts_bot;
  Counter verdicts_verified_bot;
  Counter crawlers_verified;
  Counter crawlers_failed;
  Counter crawler_lookups_dropped;
  Counter requests_blocked;
  Counter requests_would_block;
  Counter rules_matched;
  Counter rate_limited;
  Counter challenges_issued;
  Counter challenges_would;
  Counter challenges_passed;
  Counter challenges_failed;
  Counter tokens_valid;
  Counter docker_polls_failed;
  Gauge label_hosts;
  Counter rate_limited_shadow;
  Counter rejected_ip_connections;
  Counter rejected_ip_connection_rate;
  Counter alpn_mismatches;
  Counter idle_timeouts;
  Counter bytes_client_to_upstream;
  Counter bytes_upstream_to_client;
  Counter syn_captured;

  Counter events_published;
  Counter events_dropped;
  Gauge nats_connected;
  Counter nats_reconnects;
  Counter http_requests_observed;

  Gauge certificates;
  Counter acme_reloads_ok;
  Counter acme_reloads_failed;
  Gauge acme_last_reload_seconds;
};

Metrics& GlobalMetrics();

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_METRICS_H_
