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
