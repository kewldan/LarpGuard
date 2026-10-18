#include "common/metrics.h"

#include <format>
#include <iterator>
#include <string>
#include <string_view>

namespace bot_shield {
namespace {

void AppendHeader(std::string* out, std::string_view name,
                  std::string_view type, std::string_view help) {
  std::format_to(std::back_inserter(*out), "# HELP {} {}\n# TYPE {} {}\n", name,
                 help, name, type);
}

template <typename Value>
void AppendSample(std::string* out, std::string_view name,
                  std::string_view labels, Value value) {
  if (labels.empty()) {
    std::format_to(std::back_inserter(*out), "{} {}\n", name, value);
  } else {
    std::format_to(std::back_inserter(*out), "{}{{{}}} {}\n", name, labels,
                   value);
  }
}

}  // namespace

std::string Metrics::RenderPrometheus() const {
  std::string out;
  out.reserve(4096);

  AppendHeader(&out, "bot_shield_connections_total", "counter",
               "Accepted client connections.");
  AppendSample(&out, "bot_shield_connections_total", R"(listener="https")",
               connections_https.Get());
  AppendSample(&out, "bot_shield_connections_total", R"(listener="http")",
               connections_http.Get());

  AppendHeader(&out, "bot_shield_connections_active", "gauge",
               "Client connections currently open.");
  AppendSample(&out, "bot_shield_connections_active", "",
               connections_active.Get());

  AppendHeader(&out, "bot_shield_connections_rejected_total", "counter",
               "Client connections closed before routing.");
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="connection_limit")", rejected_connection_limit.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="not_tls")", rejected_not_tls.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="open_per_ip")", rejected_ip_connections.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="new_per_ip")", rejected_ip_connection_rate.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="invalid_client_hello")",
               rejected_invalid_hello.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="client_hello_timeout")", client_hello_timeouts.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="no_server_name")", rejected_no_server_name.Get());
  AppendSample(&out, "bot_shield_connections_rejected_total",
               R"(reason="pending_per_ip")", rejected_pending_per_ip.Get());

  AppendHeader(&out, "bot_shield_request_header_timeouts_total", "counter",
               "Client connections closed for slow request headers.");
  AppendSample(&out, "bot_shield_request_header_timeouts_total", "",
               request_header_timeouts.Get());

  AppendHeader(&out, "bot_shield_connection_request_limit_total", "counter",
               "Client connections ended after max_requests_per_connection.");
  AppendSample(&out, "bot_shield_connection_request_limit_total", "",
               connection_request_limits.Get());

  AppendHeader(&out, "bot_shield_h2_client_resets_total", "counter",
               "RST_STREAM frames received from HTTP/2 clients.");
  AppendSample(&out, "bot_shield_h2_client_resets_total", "",
               h2_client_resets.Get());

  AppendHeader(&out, "bot_shield_routes_total", "counter",
               "Routing decisions for TLS connections.");
  AppendSample(&out, "bot_shield_routes_total",
               R"(route="terminate",reason="certificate")",
               route_terminate.Get());
  AppendSample(&out, "bot_shield_routes_total",
               R"(route="passthrough",reason="acme_tls_alpn")",
               route_passthrough_acme_tls_alpn.Get());
  AppendSample(&out, "bot_shield_routes_total",
               R"(route="passthrough",reason="no_server_name")",
               route_passthrough_no_server_name.Get());
  AppendSample(&out, "bot_shield_routes_total",
               R"(route="passthrough",reason="policy")",
               route_passthrough_policy.Get());
  AppendSample(&out, "bot_shield_routes_total",
               R"(route="passthrough",reason="no_certificate")",
               route_passthrough_no_certificate.Get());
  AppendSample(&out, "bot_shield_routes_total",
               R"(route="passthrough",reason="not_tls")",
               route_passthrough_not_tls.Get());

  AppendHeader(&out, "bot_shield_tls_handshake_failures_total", "counter",
               "Failed TLS handshakes.");
  AppendSample(&out, "bot_shield_tls_handshake_failures_total",
               R"(side="client")", tls_handshake_failures_client.Get());
  AppendSample(&out, "bot_shield_tls_handshake_failures_total",
               R"(side="upstream")", tls_handshake_failures_upstream.Get());

  AppendHeader(&out, "bot_shield_upstream_connect_failures_total", "counter",
               "Failed TCP connects to Traefik.");
  AppendSample(&out, "bot_shield_upstream_connect_failures_total", "",
               upstream_connect_failures.Get());

  AppendHeader(&out, "bot_shield_upstream_connections_opened_total", "counter",
               "HTTP/2 connections opened to Traefik.");
  AppendSample(&out, "bot_shield_upstream_connections_opened_total", "",
               upstream_connections_opened.Get());

  AppendHeader(&out, "bot_shield_proxied_requests_total", "counter",
               "Requests handled by the HTTP proxy, by who answered.");
  AppendSample(&out, "bot_shield_proxied_requests_total",
               R"(source="upstream")", proxied_requests.Get());
  AppendSample(&out, "bot_shield_proxied_requests_total", R"(source="local")",
               local_responses.Get());

  AppendHeader(&out, "bot_shield_verdicts_total", "counter",
               "Scored requests by class.");
  AppendSample(&out, "bot_shield_verdicts_total", R"(class="human")",
               verdicts_human.Get());
  AppendSample(&out, "bot_shield_verdicts_total", R"(class="suspicious")",
               verdicts_suspicious.Get());
  AppendSample(&out, "bot_shield_verdicts_total", R"(class="bot")",
               verdicts_bot.Get());
  AppendSample(&out, "bot_shield_verdicts_total", R"(class="verified_bot")",
               verdicts_verified_bot.Get());

  AppendHeader(&out, "bot_shield_crawler_checks_total", "counter",
               "Reverse DNS checks of crawler claims by result.");
  AppendSample(&out, "bot_shield_crawler_checks_total", R"(result="verified")",
               crawlers_verified.Get());
  AppendSample(&out, "bot_shield_crawler_checks_total", R"(result="failed")",
               crawlers_failed.Get());
  AppendSample(&out, "bot_shield_crawler_checks_total", R"(result="dropped")",
               crawler_lookups_dropped.Get());

  AppendHeader(&out, "bot_shield_honeypot_hits_total", "counter",
               "Requests to honeypot paths.");
  AppendSample(&out, "bot_shield_honeypot_hits_total", "", honeypot_hits.Get());
  AppendHeader(&out, "bot_shield_behavior_signals_total", "counter",
               "Behaviour and honeypot-client signals added to verdicts.");
  AppendSample(&out, "bot_shield_behavior_signals_total", "",
               behavior_signals.Get());

  AppendHeader(&out, "bot_shield_tarpits_active", "gauge",
               "Tarpit answers trickling out now.");
  AppendSample(&out, "bot_shield_tarpits_active", "", tarpits_active.Get());
  AppendHeader(&out, "bot_shield_tarpits_total", "counter",
               "Tarpit answers by result (overflow: blocked instead).");
  AppendSample(&out, "bot_shield_tarpits_total", R"(result="started")",
               tarpits.Get());
  AppendSample(&out, "bot_shield_tarpits_total", R"(result="overflow")",
               tarpit_overflow.Get());
  AppendHeader(&out, "bot_shield_decoys_total", "counter",
               "Decoy answers with watermarked fake data.");
  AppendSample(&out, "bot_shield_decoys_total", "", decoys.Get());
  AppendHeader(&out, "bot_shield_model_flags_total", "counter",
               "Requests the model scored above model.threshold.");
  AppendSample(&out, "bot_shield_model_flags_total", "", model_flags.Get());

  AppendHeader(&out, "bot_shield_blocks_total", "counter",
               "Requests blocked, and blocks shadow mode held back.");
  AppendSample(&out, "bot_shield_blocks_total", R"(mode="enforce")",
               requests_blocked.Get());
  AppendSample(&out, "bot_shield_blocks_total", R"(mode="shadow")",
               requests_would_block.Get());

  AppendHeader(&out, "bot_shield_rate_limited_total", "counter",
               "Requests over a rate limit (shadow: let through).");
  AppendSample(&out, "bot_shield_rate_limited_total", R"(mode="enforce")",
               rate_limited.Get());
  AppendSample(&out, "bot_shield_rate_limited_total", R"(mode="shadow")",
               rate_limited_shadow.Get());

  AppendHeader(&out, "bot_shield_docker_polls_failed_total", "counter",
               "Failed reads of the Docker API.");
  AppendSample(&out, "bot_shield_docker_polls_failed_total", "",
               docker_polls_failed.Get());

  AppendHeader(&out, "bot_shield_label_hosts", "gauge",
               "Hosts configured by docker labels.");
  AppendSample(&out, "bot_shield_label_hosts", "", label_hosts.Get());

  AppendHeader(&out, "bot_shield_challenges_total", "counter",
               "JS challenges by outcome (would: held back by shadow mode).");
  AppendSample(&out, "bot_shield_challenges_total", R"(result="issued")",
               challenges_issued.Get());
  AppendSample(&out, "bot_shield_challenges_total", R"(result="would")",
               challenges_would.Get());
  AppendSample(&out, "bot_shield_challenges_total", R"(result="passed")",
               challenges_passed.Get());
  AppendSample(&out, "bot_shield_challenges_total", R"(result="failed")",
               challenges_failed.Get());

  AppendHeader(&out, "bot_shield_challenge_endpoint_limited_total", "counter",
               "Requests to /__bs/* refused by challenge.endpoint_rate.");
  AppendSample(&out, "bot_shield_challenge_endpoint_limited_total", "",
               challenge_endpoint_limited.Get());

  AppendHeader(&out, "bot_shield_attack_hosts", "gauge",
               "Under-attack entries (hosts, or * for all) in effect.");
  AppendSample(&out, "bot_shield_attack_hosts", "", attack_hosts.Get());

  AppendHeader(&out, "bot_shield_attack_auto_activations_total", "counter",
               "Hosts put under attack by attack.auto_rps.");
  AppendSample(&out, "bot_shield_attack_auto_activations_total", "",
               attack_auto_activations.Get());

  AppendHeader(&out, "bot_shield_attack_challenges_total", "counter",
               "Challenges issued because the host was under attack.");
  AppendSample(&out, "bot_shield_attack_challenges_total", "",
               attack_challenges.Get());

  AppendHeader(&out, "bot_shield_tokens_valid_total", "counter",
               "Requests carrying a valid clearance token.");
  AppendSample(&out, "bot_shield_tokens_valid_total", "", tokens_valid.Get());

  AppendHeader(&out, "bot_shield_rules_matched_total", "counter",
               "Rule matches (score, allow and block rules).");
  AppendSample(&out, "bot_shield_rules_matched_total", "", rules_matched.Get());

  AppendHeader(&out, "bot_shield_websocket_tunnels_total", "counter",
               "Upgraded (WebSocket) connections tunnelled to Traefik.");
  AppendSample(&out, "bot_shield_websocket_tunnels_total", "",
               websocket_tunnels.Get());

  AppendHeader(&out, "bot_shield_alpn_mismatches_total", "counter",
               "Upstream negotiated a different ALPN than the client.");
  AppendSample(&out, "bot_shield_alpn_mismatches_total", "",
               alpn_mismatches.Get());

  AppendHeader(&out, "bot_shield_idle_timeouts_total", "counter",
               "Proxied connections closed for inactivity.");
  AppendSample(&out, "bot_shield_idle_timeouts_total", "", idle_timeouts.Get());

  AppendHeader(&out, "bot_shield_bytes_total", "counter",
               "Proxied payload bytes.");
  AppendSample(&out, "bot_shield_bytes_total",
               R"(direction="client_to_upstream")",
               bytes_client_to_upstream.Get());
  AppendSample(&out, "bot_shield_bytes_total",
               R"(direction="upstream_to_client")",
               bytes_upstream_to_client.Get());

  AppendHeader(&out, "bot_shield_syn_captured_total", "counter",
               "Connections with a captured TCP SYN (Linux only).");
  AppendSample(&out, "bot_shield_syn_captured_total", "", syn_captured.Get());

  AppendHeader(&out, "bot_shield_http_requests_observed_total", "counter",
               "HTTP requests seen by the passive taps.");
  AppendSample(&out, "bot_shield_http_requests_observed_total", "",
               http_requests_observed.Get());

  AppendHeader(&out, "bot_shield_events_total", "counter",
               "Analytics events by outcome.");
  AppendSample(&out, "bot_shield_events_total", R"(result="published")",
               events_published.Get());
  AppendSample(&out, "bot_shield_events_total", R"(result="dropped")",
               events_dropped.Get());

  AppendHeader(&out, "bot_shield_nats_connected", "gauge",
               "1 while connected to NATS.");
  AppendSample(&out, "bot_shield_nats_connected", "", nats_connected.Get());

  AppendHeader(&out, "bot_shield_nats_reconnects_total", "counter",
               "NATS reconnect attempts.");
  AppendSample(&out, "bot_shield_nats_reconnects_total", "",
               nats_reconnects.Get());

  AppendHeader(&out, "bot_shield_certificates", "gauge",
               "Certificates loaded from acme.json.");
  AppendSample(&out, "bot_shield_certificates", "", certificates.Get());

  AppendHeader(&out, "bot_shield_acme_reloads_total", "counter",
               "acme.json reload attempts.");
  AppendSample(&out, "bot_shield_acme_reloads_total", R"(result="ok")",
               acme_reloads_ok.Get());
  AppendSample(&out, "bot_shield_acme_reloads_total", R"(result="error")",
               acme_reloads_failed.Get());

  AppendHeader(&out, "bot_shield_acme_last_reload_timestamp_seconds", "gauge",
               "Unix time of the last successful acme.json load.");
  AppendSample(&out, "bot_shield_acme_last_reload_timestamp_seconds", "",
               acme_last_reload_seconds.Get());

  return out;
}

Metrics& GlobalMetrics() {
  static Metrics metrics;
  return metrics;
}

}  // namespace bot_shield
