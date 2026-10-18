#include "config/config.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/host.h"
#include "common/log.h"
#include "ratelimit/limits.h"
#include "score/policy.h"
#include "score/rules.h"

namespace bot_shield {
namespace {

bool ParseUnsigned(std::string_view text, uint64_t* value) {
  if (text.empty()) return false;
  // from_chars takes a [begin, end) range, so no terminator is needed.
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* begin = text.data();
  const char* end = begin + text.size();
  auto [ptr, ec] = std::from_chars(begin, end, *value);
  return ec == std::errc() && ptr == end;
}

// Fails on keys of `node` outside `allowed`.
bool CheckKeys(const YAML::Node& node, std::string_view section,
               std::initializer_list<std::string_view> allowed,
               std::string* error) {
  if (!node.IsMap()) {
    *error = std::format("{}: expected a mapping", section);
    return false;
  }
  for (const auto& item : node) {
    const auto key = item.first.as<std::string>();
    if (std::ranges::find(allowed, key) == allowed.end()) {
      *error = section.empty()
                   ? std::format("unknown key '{}'", key)
                   : std::format("{}: unknown key '{}'", section, key);
      return false;
    }
  }
  return true;
}

std::string Path(std::string_view section, std::string_view key) {
  return section.empty() ? std::string(key)
                         : std::format("{}.{}", section, key);
}

bool ReadDuration(const YAML::Node& parent, std::string_view section,
                  const char* key, std::chrono::milliseconds* out,
                  std::string* error) {
  const YAML::Node node = parent[key];
  if (!node) return true;
  if (!ParseDuration(node.as<std::string>(), out) || out->count() <= 0) {
    *error = std::format("{}: expected a positive duration like 5s or 250ms",
                         Path(section, key));
    return false;
  }
  return true;
}

bool ReadEndpoint(const YAML::Node& parent, std::string_view section,
                  const char* key, Endpoint* out, std::string* error) {
  const YAML::Node node = parent[key];
  if (!node) return true;
  if (!ParseEndpoint(node.as<std::string>(), out)) {
    *error = std::format("{}: expected host:port", Path(section, key));
    return false;
  }
  return true;
}

// An empty string disables the endpoint.
bool ReadOptionalEndpoint(const YAML::Node& parent, std::string_view section,
                          const char* key, std::optional<Endpoint>* out,
                          std::string* error) {
  const YAML::Node node = parent[key];
  if (!node) return true;
  const auto text = node.IsNull() ? std::string() : node.as<std::string>();
  if (text.empty()) {
    out->reset();
    return true;
  }
  Endpoint endpoint;
  if (!ParseEndpoint(text, &endpoint)) {
    *error = std::format("{}: expected host:port or \"\"", Path(section, key));
    return false;
  }
  *out = endpoint;
  return true;
}

bool ParseListen(const YAML::Node& node, Config* config, std::string* error) {
  if (!CheckKeys(node, "listen", {"http", "https"}, error)) return false;
  if (!ReadOptionalEndpoint(node, "listen", "http", &config->listen_http,
                            error)) {
    return false;
  }
  return ReadEndpoint(node, "listen", "https", &config->listen_https, error);
}

bool ParseTraefik(const YAML::Node& node, Config* config, std::string* error) {
  if (!CheckKeys(node, "traefik",
                 {"acme_json", "acme_reload_interval", "upstream_https",
                  "upstream_http", "proxy_protocol", "tls_verify", "pool_size"},
                 error)) {
    return false;
  }
  if (node["acme_json"]) {
    config->acme_json = node["acme_json"].as<std::string>();
  }
  if (node["proxy_protocol"]) {
    config->proxy_protocol = node["proxy_protocol"].as<bool>();
  }
  if (node["tls_verify"]) {
    config->upstream_tls_verify = node["tls_verify"].as<bool>();
  }
  if (node["pool_size"]) {
    const auto value = node["pool_size"].as<int64_t>();
    if (value <= 0 || value > 64) {
      *error = "traefik.pool_size: expected 1..64";
      return false;
    }
    config->upstream_pool_size = static_cast<std::size_t>(value);
  }
  return ReadDuration(node, "traefik", "acme_reload_interval",
                      &config->acme_reload_interval, error) &&
         ReadEndpoint(node, "traefik", "upstream_https",
                      &config->upstream_https, error) &&
         ReadEndpoint(node, "traefik", "upstream_http", &config->upstream_http,
                      error);
}

bool ParseTimeouts(const YAML::Node& node, Config* config, std::string* error) {
  if (!CheckKeys(node, "timeouts",
                 {"client_hello", "tls_handshake", "upstream_connect", "idle",
                  "drain", "upstream_idle"},
                 error)) {
    return false;
  }
  return ReadDuration(node, "timeouts", "client_hello",
                      &config->client_hello_timeout, error) &&
         ReadDuration(node, "timeouts", "tls_handshake",
                      &config->tls_handshake_timeout, error) &&
         ReadDuration(node, "timeouts", "upstream_connect",
                      &config->upstream_connect_timeout, error) &&
         ReadDuration(node, "timeouts", "idle", &config->idle_timeout, error) &&
         ReadDuration(node, "timeouts", "drain", &config->drain_timeout,
                      error) &&
         ReadDuration(node, "timeouts", "upstream_idle",
                      &config->upstream_idle_timeout, error);
}

bool ParseEvents(const YAML::Node& node, Config* config, std::string* error) {
  if (!CheckKeys(node, "events",
                 {"nats", "subject_prefix", "token", "user", "password",
                  "max_queue", "ip_salt", "requests"},
                 error)) {
    return false;
  }
  if (const YAML::Node nats = node["nats"]) {
    std::string text = nats.IsNull() ? std::string() : nats.as<std::string>();
    if (text.starts_with("nats://")) text.erase(0, 7);
    if (text.empty()) {
      config->events_nats.reset();
    } else {
      Endpoint endpoint;
      if (!ParseEndpoint(text, &endpoint)) {
        *error = "events.nats: expected host:port or nats://host:port";
        return false;
      }
      config->events_nats = endpoint;
    }
  }
  if (node["subject_prefix"]) {
    config->events_subject_prefix = node["subject_prefix"].as<std::string>();
    if (config->events_subject_prefix.empty() ||
        config->events_subject_prefix.find_first_of(" \t*>") !=
            std::string::npos) {
      *error = "events.subject_prefix: expected a plain NATS subject";
      return false;
    }
  }
  if (node["token"]) config->events_token = node["token"].as<std::string>();
  if (node["user"]) config->events_user = node["user"].as<std::string>();
  if (node["password"]) {
    config->events_password = node["password"].as<std::string>();
  }
  if (node["max_queue"]) {
    const auto value = node["max_queue"].as<int64_t>();
    if (value <= 0) {
      *error = "events.max_queue: expected a positive number";
      return false;
    }
    config->events_max_queue = static_cast<std::size_t>(value);
  }
  if (node["ip_salt"]) {
    config->events_ip_salt = node["ip_salt"].as<std::string>();
  }
  if (node["requests"]) config->events_requests = node["requests"].as<bool>();
  return true;
}

bool ParseMode(const YAML::Node& node, std::string_view where, bool* enforce,
               std::string* error) {
  const auto value = node.as<std::string>();
  if (value == "shadow") {
    *enforce = false;
  } else if (value == "enforce") {
    *enforce = true;
  } else {
    *error = std::format("{}: expected shadow or enforce", where);
    return false;
  }
  return true;
}

bool ParsePolicy(const YAML::Node& node, Config* config, std::string* error) {
  if (!CheckKeys(node, "policy",
                 {"thresholds", "actions", "block_status", "hosts"}, error)) {
    return false;
  }
  PolicySettings& policy = config->policy;
  if (const YAML::Node thresholds = node["thresholds"]) {
    if (!CheckKeys(thresholds, "policy.thresholds", {"suspicious", "bot"},
                   error)) {
      return false;
    }
    if (thresholds["suspicious"]) {
      policy.suspicious_threshold = thresholds["suspicious"].as<int>();
    }
    if (thresholds["bot"]) policy.bot_threshold = thresholds["bot"].as<int>();
    if (policy.suspicious_threshold < 1 || policy.bot_threshold > 100 ||
        policy.suspicious_threshold > policy.bot_threshold) {
      *error = "policy.thresholds: expected 1 <= suspicious <= bot <= 100";
      return false;
    }
  }
  if (const YAML::Node actions = node["actions"]) {
    if (!CheckKeys(actions, "policy.actions", {"suspicious", "bot"}, error)) {
      return false;
    }
    if ((actions["suspicious"] &&
         !ParseAction(actions["suspicious"].as<std::string>(),
                      &policy.suspicious_action)) ||
        (actions["bot"] &&
         !ParseAction(actions["bot"].as<std::string>(), &policy.bot_action))) {
      *error = "policy.actions: expected allow or block";
      return false;
    }
  }
  if (node["block_status"]) {
    policy.block_status = node["block_status"].as<int>();
    if (policy.block_status < 400 || policy.block_status > 599) {
      *error = "policy.block_status: expected 400..599";
      return false;
    }
  }
  if (const YAML::Node hosts = node["hosts"]) {
    if (!hosts.IsMap()) {
      *error = "policy.hosts: expected host: shadow|enforce";
      return false;
    }
    policy.host_modes.clear();
    for (const auto& item : hosts) {
      const std::string host = NormalizeHost(item.first.as<std::string>());
      const std::string_view name =
          host.starts_with("*.") ? std::string_view(host).substr(2) : host;
      if (!IsValidHostName(name)) {
        *error = std::format("policy.hosts: invalid host '{}'", host);
        return false;
      }
      HostMode mode = HostMode::kShadow;
      if (!ParseHostMode(item.second.as<std::string>(), &mode)) {
        *error = "policy.hosts: expected shadow, enforce or off";
        return false;
      }
      policy.host_modes.emplace_back(host, mode);
    }
  }
  return true;
}

std::vector<std::string> ReadStrings(const YAML::Node& node) {
  std::vector<std::string> out;
  if (!node) return out;
  if (node.IsScalar()) {
    out.push_back(node.as<std::string>());
    return out;
  }
  for (const auto& item : node) out.push_back(item.as<std::string>());
  return out;
}

bool ParseRateLimits(const YAML::Node& node, Config* config,
                     std::string* error) {
  if (!node.IsSequence()) {
    *error = "rate_limits: expected a list";
    return false;
  }
  config->rate_limits.clear();
  for (const auto& item : node) {
    if (!CheckKeys(item, "rate_limits[]",
                   {"name", "hosts", "paths", "methods", "classes", "key",
                    "rate", "burst"},
                   error)) {
      return false;
    }
    RateLimitSpec spec;
    if (item["name"]) spec.name = item["name"].as<std::string>();
    spec.hosts = ReadStrings(item["hosts"]);
    spec.paths = ReadStrings(item["paths"]);
    spec.methods = ReadStrings(item["methods"]);
    spec.classes = ReadStrings(item["classes"]);
    spec.key = ReadStrings(item["key"]);
    if (!item["rate"] ||
        !ParseRate(item["rate"].as<std::string>(), &spec.count, &spec.period)) {
      *error =
          std::format("rate_limits '{}': rate must be like 120/m", spec.name);
      return false;
    }
    spec.burst = item["burst"] ? item["burst"].as<int64_t>() : spec.count;
    config->rate_limits.push_back(std::move(spec));
  }
  RateLimitSet compiled;
  return RateLimitSet::Compile(config->rate_limits, &compiled, error);
}

bool ParseRoot(const YAML::Node& root, Config* config, std::string* error) {
  if (!CheckKeys(root, "",
                 {"listen", "workers", "traefik", "passthrough_hosts",
                  "non_tls", "timeouts", "max_connections", "events", "mode",
                  "policy", "rules", "rate_limits", "connection_limits",
                  "docker", "fingerprints", "metrics", "log_level"},
                 error)) {
    return false;
  }
  if (root["listen"] && !ParseListen(root["listen"], config, error)) {
    return false;
  }
  if (root["workers"]) {
    config->workers = root["workers"].as<int>();
    if (config->workers < 0 || config->workers > 1024) {
      *error = "workers: expected 0..1024 (0 = one per CPU)";
      return false;
    }
  }
  if (root["traefik"] && !ParseTraefik(root["traefik"], config, error)) {
    return false;
  }
  if (const YAML::Node hosts = root["passthrough_hosts"]) {
    if (!hosts.IsSequence()) {
      *error = "passthrough_hosts: expected a list";
      return false;
    }
    config->passthrough_hosts.clear();
    for (const auto& item : hosts) {
      const std::string host = NormalizeHost(item.as<std::string>());
      const std::string_view name =
          host.starts_with("*.") ? std::string_view(host).substr(2) : host;
      if (!IsValidHostName(name)) {
        *error = std::format("passthrough_hosts: invalid host '{}'", host);
        return false;
      }
      config->passthrough_hosts.push_back(host);
    }
  }
  if (root["non_tls"]) {
    const auto value = root["non_tls"].as<std::string>();
    if (value == "reject") {
      config->non_tls = NonTlsAction::kReject;
    } else if (value == "passthrough") {
      config->non_tls = NonTlsAction::kPassthrough;
    } else {
      *error = "non_tls: expected reject or passthrough";
      return false;
    }
  }
  if (root["timeouts"] && !ParseTimeouts(root["timeouts"], config, error)) {
    return false;
  }
  if (root["max_connections"]) {
    const auto value = root["max_connections"].as<int64_t>();
    if (value <= 0) {
      *error = "max_connections: expected a positive number";
      return false;
    }
    config->max_connections = static_cast<std::size_t>(value);
  }
  if (root["events"] && !ParseEvents(root["events"], config, error)) {
    return false;
  }
  if (root["mode"] &&
      !ParseMode(root["mode"], "mode", &config->policy.enforce, error)) {
    return false;
  }
  if (root["policy"] && !ParsePolicy(root["policy"], config, error)) {
    return false;
  }
  if (const YAML::Node rules = root["rules"]) {
    if (!rules.IsSequence()) {
      *error = "rules: expected a list";
      return false;
    }
    config->rules.clear();
    for (const auto& item : rules) {
      if (!CheckKeys(item, "rules[]", {"name", "when", "action", "score"},
                     error)) {
        return false;
      }
      RuleSpec spec;
      if (item["name"]) spec.name = item["name"].as<std::string>();
      if (item["when"]) spec.when = item["when"].as<std::string>();
      if (item["action"]) spec.action = item["action"].as<std::string>();
      if (item["score"]) spec.score = item["score"].as<int>();
      config->rules.push_back(std::move(spec));
    }
    // Compile now so --check-config reports bad rules.
    RuleSet compiled;
    std::string rule_error;
    if (!RuleSet::Compile(config->rules, &compiled, &rule_error)) {
      *error = "rules: " + rule_error;
      return false;
    }
  }
  if (const YAML::Node limits = root["rate_limits"]) {
    if (!ParseRateLimits(limits, config, error)) return false;
  }
  if (const YAML::Node limits = root["connection_limits"]) {
    if (!CheckKeys(limits, "connection_limits",
                   {"open_per_ip", "new_per_ip", "new_burst_per_ip"}, error)) {
      return false;
    }
    if (limits["open_per_ip"]) {
      const auto value = limits["open_per_ip"].as<int64_t>();
      if (value < 0) {
        *error = "connection_limits.open_per_ip: expected >= 0";
        return false;
      }
      config->open_connections_per_ip = static_cast<std::size_t>(value);
    }
    if (limits["new_per_ip"]) {
      const auto text = limits["new_per_ip"].as<std::string>();
      if (text.empty()) {
        config->new_connections_per_ip = 0;
      } else if (!ParseRate(text, &config->new_connections_per_ip,
                            &config->new_connections_period)) {
        *error = "connection_limits.new_per_ip: expected a rate like 30/s";
        return false;
      }
    }
    if (limits["new_burst_per_ip"]) {
      config->new_connections_burst = limits["new_burst_per_ip"].as<int64_t>();
      if (config->new_connections_burst < 1) {
        *error = "connection_limits.new_burst_per_ip: expected >= 1";
        return false;
      }
    }
  }
  if (const YAML::Node docker = root["docker"]) {
    if (!CheckKeys(docker, "docker", {"socket", "poll_interval"}, error) ||
        !ReadDuration(docker, "docker", "poll_interval",
                      &config->docker_poll_interval, error)) {
      return false;
    }
    if (docker["socket"]) {
      config->docker_socket =
          docker["socket"].IsNull() ? "" : docker["socket"].as<std::string>();
    }
  }
  if (const YAML::Node fingerprints = root["fingerprints"]) {
    if (!CheckKeys(fingerprints, "fingerprints", {"library"}, error)) {
      return false;
    }
    if (fingerprints["library"]) {
      config->fingerprint_library = fingerprints["library"].as<std::string>();
    }
  }
  if (const YAML::Node metrics = root["metrics"]) {
    if (!CheckKeys(metrics, "metrics", {"listen"}, error) ||
        !ReadOptionalEndpoint(metrics, "metrics", "listen",
                              &config->metrics_listen, error)) {
      return false;
    }
  }
  if (root["log_level"] && !log::ParseLevel(root["log_level"].as<std::string>(),
                                            &config->log_level)) {
    *error = "log_level: expected debug, info, warn or error";
    return false;
  }
  return true;
}

}  // namespace

std::string Endpoint::ToString() const {
  if (host.find(':') != std::string::npos) {
    return std::format("[{}]:{}", host, port);
  }
  return std::format("{}:{}", host, port);
}

bool ParseDuration(std::string_view text, std::chrono::milliseconds* duration) {
  struct Unit {
    std::string_view suffix;
    int64_t millis;
  };
  // "ms" must be tried before "m" and "s".
  static constexpr Unit kUnits[] = {{"ms", 1},
                                    {"s", 1000},
                                    {"m", int64_t{60} * 1000},
                                    {"h", int64_t{60} * 60 * 1000}};
  for (const Unit& unit : kUnits) {
    if (!text.ends_with(unit.suffix)) continue;
    uint64_t value = 0;
    if (!ParseUnsigned(text.substr(0, text.size() - unit.suffix.size()),
                       &value) ||
        std::cmp_greater(value, INT64_MAX / unit.millis)) {
      return false;
    }
    *duration =
        std::chrono::milliseconds(static_cast<int64_t>(value) * unit.millis);
    return true;
  }
  return false;
}

bool ParseEndpoint(std::string_view text, Endpoint* endpoint) {
  std::string_view host;
  std::string_view port;
  if (text.starts_with('[')) {
    const auto close = text.find(']');
    if (close == std::string_view::npos || close + 1 >= text.size() ||
        text[close + 1] != ':') {
      return false;
    }
    host = text.substr(1, close - 1);
    port = text.substr(close + 2);
    if (host.empty()) return false;
  } else {
    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos) return false;
    host = text.substr(0, colon);
    port = text.substr(colon + 1);
    if (host.find(':') != std::string_view::npos) return false;
    if (host.empty()) host = "0.0.0.0";
  }
  uint64_t port_number = 0;
  if (!ParseUnsigned(port, &port_number) || port_number == 0 ||
      port_number > 65535) {
    return false;
  }
  endpoint->host = std::string(host);
  endpoint->port = static_cast<uint16_t>(port_number);
  return true;
}

bool ParseConfig(std::string_view yaml, Config* config, std::string* error) {
  try {
    const YAML::Node root = YAML::Load(std::string(yaml));
    if (root.IsNull()) return true;
    return ParseRoot(root, config, error);
  } catch (const YAML::Exception& e) {
    *error = e.what();
    return false;
  }
}

bool LoadConfigFile(const std::string& path, Config* config,
                    std::string* error) {
  std::ifstream file(path);
  if (!file) {
    *error = std::format("cannot open {}", path);
    return false;
  }
  std::stringstream contents;
  contents << file.rdbuf();
  if (!ParseConfig(contents.str(), config, error)) {
    *error = std::format("{}: {}", path, *error);
    return false;
  }
  return true;
}

}  // namespace bot_shield
