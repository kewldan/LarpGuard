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
  Counter connections_quic;
  Gauge connections_active;
  Counter rejected_connection_limit;
  Counter rejected_not_tls;
  Counter rejected_invalid_hello;
  Counter client_hello_timeouts;
  Counter rejected_no_server_name;
  Counter rejected_pending_per_ip;
  Counter request_header_timeouts;
  Counter connection_request_limits;
  Counter h2_client_resets;
  Counter challenge_endpoint_limited;
  Gauge attack_hosts;
  Counter attack_auto_activations;
  Counter attack_challenges;

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
  Counter honeypot_hits;
  Counter behavior_signals;
  Gauge tarpits_active;
  Counter tarpits;
  Counter tarpit_overflow;
  Counter decoys;
  Counter model_flags;
  Counter quic_datagrams;
  Counter quic_handshakes;
  Counter quic_retries;
  Counter quic_rejected;
  Counter quic_send_errors;
  Gauge quic_connections;
  Counter requests_blocked;
  Counter requests_would_block;
  Counter rules_matched;
  Counter rate_limited;
  Counter challenges_issued;
  Counter challenges_would;
  Counter challenges_passed;
  Counter challenges_failed;
  // JS challenges that ended in a CAPTCHA instead (suspicious or soft).
  Counter challenge_escalations;
  Counter captchas_issued;
  Counter captchas_passed;
  Counter captchas_failed;
  // Web Bot Auth signatures by result.
  Counter signed_verified;
  Counter signed_invalid;
  // Crawler claims decided by published IP ranges.
  Counter crawler_ranges_verified;
  Counter crawler_ranges_failed;
  // Datasets in memory.
  Gauge asn_ranges;
  Gauge crawler_range_sets;
  // XDP pre-filter (absolute counts read from the program).
  Gauge xdp_attached;
  Gauge xdp_passed;
  Gauge xdp_blocked;
  Gauge xdp_syn_rate;
  Gauge xdp_invalid;
  Gauge xdp_fragment;
  Gauge xdp_fail_open;
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
