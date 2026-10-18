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

// What to do with a connection on the HTTPS listener that does not start with
// a TLS handshake record.
enum class NonTlsAction { kReject, kPassthrough };

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
  NonTlsAction non_tls = NonTlsAction::kReject;

  std::chrono::milliseconds client_hello_timeout{5000};
  std::chrono::milliseconds tls_handshake_timeout{10000};
  std::chrono::milliseconds upstream_connect_timeout{5000};
  std::chrono::milliseconds idle_timeout{300000};
  std::chrono::milliseconds drain_timeout{30000};

  std::size_t max_connections = 100000;

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
  // Per-IP limits applied when a connection is accepted, before TLS
  // ("connection_limits"); 0 disables each.
  std::size_t open_connections_per_ip = 0;
  int64_t new_connections_per_ip = 0;
  std::chrono::milliseconds new_connections_period{1000};
  int64_t new_connections_burst = 1;
  // JS challenge ("challenge" section). Keys file: see TokenKeys::Load; empty
  // means a random key per start (tokens do not survive restarts).
  std::string challenge_keys_file;
  std::chrono::milliseconds challenge_token_ttl{std::chrono::hours(12)};
  int challenge_suspicious_difficulty = 16;
  int challenge_bot_difficulty = 19;
  int challenge_token_credit = 40;
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
