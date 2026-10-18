#ifndef BOT_SHIELD_CONFIG_CONFIG_H_
#define BOT_SHIELD_CONFIG_CONFIG_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/log.h"
#include "ratelimit/limits.h"
#include "score/policy.h"
#include "score/rules.h"

namespace bot_shield {

// "host:port" as written in the config; resolved at startup.
struct Endpoint {
  std::string ToString() const;

  std::string host;
  uint16_t port = 0;

  friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

// What to do with an HTTPS-port connection the gateway cannot route by
// certificate: one that does not start with a TLS handshake record, or a
// ClientHello without SNI.
enum class FallbackRoute { kReject, kPassthrough };

struct Config {
  // Listeners. `listen_http` is optional: without it port 80 stays with
  // whatever owns it (normally Traefik).
  std::optional<Endpoint> listen_http = Endpoint{"0.0.0.0", 80};
  Endpoint listen_https{"0.0.0.0", 443};

  // 0 means one worker per hardware thread.
  int workers = 0;

  // Traefik integration.
  std::string acme_json = "/traefik/acme.json";
  std::chrono::milliseconds acme_reload_interval{2000};
  Endpoint upstream_https{"127.0.0.1", 8443};
  Endpoint upstream_http{"127.0.0.1", 8080};
  bool proxy_protocol = true;
  bool upstream_tls_verify = false;
  // HTTP/2 connections to Traefik per SNI and worker.
  std::size_t upstream_pool_size = 4;
  std::chrono::milliseconds upstream_idle_timeout{90000};

  // Hosts never terminated here (exact names or "*.parent").
  std::vector<std::string> passthrough_hosts;
  FallbackRoute non_tls = FallbackRoute::kReject;
  // ClientHello without SNI. Passed through, Traefik would route it by the
  // Host header and skip every check here, so it is rejected by default.
  FallbackRoute no_sni = FallbackRoute::kReject;

  std::chrono::milliseconds client_hello_timeout{5000};
  std::chrono::milliseconds tls_handshake_timeout{10000};
  std::chrono::milliseconds upstream_connect_timeout{5000};
  std::chrono::milliseconds idle_timeout{300000};
  // From the end of the TLS handshake (or the first byte of a keep-alive
  // request) until the request headers are complete.
  std::chrono::milliseconds request_headers_timeout{10000};
  std::chrono::milliseconds drain_timeout{30000};

  std::size_t max_connections = 100000;
  // Requests on one client connection; then HTTP/1.1 closes it and HTTP/2
  // sends GOAWAY, so a client has to reconnect (and pass the connection
  // limits again).
  std::size_t max_requests_per_connection = 1000;

  // Analytics events. No NATS server means no events (and no HTTP taps).
  std::optional<Endpoint> events_nats;
  std::string events_subject_prefix = "botshield.events";
  std::string events_token;
  std::string events_user;
  std::string events_password;
  std::size_t events_max_queue = 100000;
  // Key for IP hashes; empty means a random key per process start.
  std::string events_ip_salt;
  // One event per HTTP request (passive taps on decrypted traffic).
  bool events_requests = true;

  // Verdicts and what to do with them ("mode" and "policy" sections).
  PolicySettings policy;
  // Ordered rules on top of the score ("rules" section).
  std::vector<RuleSpec> rules;
  // Request rate limits ("rate_limits" section).
  std::vector<RateLimitSpec> rate_limits;
  // Action "throttle": a lower limit for the requests it applies to
  // ("throttle" section: rate, burst, key; no filters). Unset: throttle
  // acts like allow.
  std::optional<RateLimitSpec> throttle;
  // Per-IP limits applied when a connection is accepted, before TLS
  // ("connection_limits"); 0 disables each.
  std::size_t open_connections_per_ip = 0;
  int64_t new_connections_per_ip = 0;
  std::chrono::milliseconds new_connections_period{1000};
  int64_t new_connections_burst = 1;
  // Connections per IP that have not finished their first request's headers
  // (ClientHello, handshake, headers): bounds slowloris-style clients.
  std::size_t pending_connections_per_ip = 128;
  // HTTP/3 ("http3" section): QUIC on the HTTPS port (UDP), advertised with
  // Alt-Svc. Traefik's own HTTP/3 must stay off (ADR-011).
  bool http3_enabled = false;
  std::chrono::milliseconds http3_idle_timeout{30000};
  bool http3_retry = true;
  std::size_t http3_max_connections = 10000;  // Per worker.
  std::chrono::milliseconds http3_alt_svc_max_age{std::chrono::hours(24)};
  // Port in Alt-Svc; 0: the HTTPS listen port.
  uint16_t http3_advertise_port = 0;
  // Known crawlers ("crawlers" section): verify search crawlers by reverse
  // DNS, and what to do with AI crawlers (unset: score them like anyone).
  bool crawlers_verify = true;
  std::optional<Action> crawlers_ai;
  // Behaviour signals ("behavior" section, docs/architecture.md 5.4).
  bool behavior_enabled = true;
  std::chrono::milliseconds behavior_window{std::chrono::minutes(10)};
  std::size_t behavior_max_clients = 500'000;
  // Honeypot paths (globs): a request marks its address and fingerprint
  // for `honeypot_ttl` (needs behavior). Only paths no site here serves.
  std::vector<std::string> honeypot_paths = {
      "/.env",      "/.env.*",        "/.git/*",     "/.svn/*",
      "/.aws/*",    "/.ssh/*",        "/.DS_Store",  "/wp-config.php*",
      "/.htpasswd", "/server-status", "/phpinfo.php"};
  std::chrono::milliseconds honeypot_ttl{std::chrono::hours(1)};
  // Action "tarpit": `tarpit_chunk` bytes every `tarpit_interval` for
  // `tarpit_duration`; above `tarpit_max_active` at once, block instead.
  std::chrono::milliseconds tarpit_duration{std::chrono::seconds(30)};
  std::chrono::milliseconds tarpit_interval{std::chrono::seconds(1)};
  std::size_t tarpit_chunk = 16;
  std::size_t tarpit_max_active = 1000;
  // Action "decoy": templates with {{watermark}}; empty: built-in ones.
  std::string decoy_html;
  std::string decoy_json;
  // Model signal ("model" section): gradient-boosted trees from
  // tools/train_model.py; "" = no model. Above `model_threshold` the
  // request gets signal "model". `model_log_features` puts the feature
  // vector in req events (training data), with or without a model.
  std::string model_file;
  double model_threshold = 0.8;
  bool model_log_features = true;
  // JS challenge ("challenge" section). Keys file: see TokenKeys::Load; empty
  // means a random key per start (tokens do not survive restarts).
  std::string challenge_keys_file;
  std::chrono::milliseconds challenge_token_ttl{std::chrono::hours(12)};
  int challenge_suspicious_difficulty = 16;
  int challenge_bot_difficulty = 19;
  int challenge_token_credit = 40;
  // Requests to /__bs/* per client IP (challenge pages and solutions); they
  // are answered here and bypass the other rate limits.
  int64_t challenge_endpoint_rate = 30;
  std::chrono::milliseconds challenge_endpoint_period{60000};
  int64_t challenge_endpoint_burst = 10;
  // Under-attack mode ("attack" section): a host gets it automatically when
  // its request rate stays above `attack_auto_rps` (0 = only by the admin
  // API) and keeps it for `attack_auto_duration`.
  int64_t attack_auto_rps = 0;
  std::chrono::milliseconds attack_auto_duration{std::chrono::minutes(10)};
  // Admin API on a unix socket (mode 0600); empty disables.
  std::string admin_socket;
  // Operational lists survive restarts in this JSON file; empty: memory.
  std::string admin_state_file;
  // Recent decisions kept for GET /decisions.
  std::size_t admin_decisions = 10000;
  // Docker Engine socket for botshield.* label policies; empty disables.
  std::string docker_socket;
  std::chrono::milliseconds docker_poll_interval{5000};
  // Fingerprint library file; empty means the built-in one.
  std::string fingerprint_library;

  std::optional<Endpoint> metrics_listen = Endpoint{"127.0.0.1", 9900};
  log::Level log_level = log::Level::kInfo;
};

// Parses "250ms", "5s", "2m", "1h".
bool ParseDuration(std::string_view text, std::chrono::milliseconds* duration);

// Parses "1.2.3.4:443", "[::1]:443", "name:80" and ":443" (all addresses).
bool ParseEndpoint(std::string_view text, Endpoint* endpoint);

// Parses YAML on top of the defaults in `*config`. Unknown keys are errors so
// typos do not silently fall back to defaults.
bool ParseConfig(std::string_view yaml, Config* config, std::string* error);
bool LoadConfigFile(const std::string& path, Config* config,
                    std::string* error);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CONFIG_CONFIG_H_
