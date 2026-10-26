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
#include "net/geoip.h"
#include "net/http_client.h"
#include "net/threat_lists.h"
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

bool ReadFallbackRoute(const YAML::Node& parent, const char* key,
                       FallbackRoute* out, std::string* error) {
  const YAML::Node node = parent[key];
  if (!node) return true;
  const auto value = node.as<std::string>();
  if (value == "reject") {
    *out = FallbackRoute::kReject;
  } else if (value == "passthrough") {
    *out = FallbackRoute::kPassthrough;
  } else {
    *error = std::format("{}: expected reject or passthrough", key);
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
                 {"client_hello", "tls_handshake", "request_headers",
                  "request_body", "request_body_min_rate", "upstream_connect",
                  "idle", "drain", "upstream_idle"},
                 error)) {
    return false;
  }
  if (const YAML::Node rate = node["request_body_min_rate"]) {
    const auto value = rate.as<int64_t>();
    if (value < 0) {
      *error = "timeouts.request_body_min_rate: expected bytes per second >= 0";
      return false;
    }
    config->request_body_min_rate = value;
  }
  return ReadDuration(node, "timeouts", "request_body",
                      &config->request_body_timeout, error) &&
         ReadDuration(node, "timeouts", "client_hello",
                      &config->client_hello_timeout, error) &&
         ReadDuration(node, "timeouts", "tls_handshake",
                      &config->tls_handshake_timeout, error) &&
         ReadDuration(node, "timeouts", "request_headers",
                      &config->request_headers_timeout, error) &&
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
    if (!CheckKeys(actions, "policy.actions",
                   {"suspicious", "bot", "verified_bot"}, error)) {
      return false;
    }
    if ((actions["suspicious"] &&
         !ParseAction(actions["suspicious"].as<std::string>(),
                      &policy.suspicious_action)) ||
        (actions["bot"] &&
         !ParseAction(actions["bot"].as<std::string>(), &policy.bot_action)) ||
        (actions["verified_bot"] &&
         !ParseAction(actions["verified_bot"].as<std::string>(),
                      &policy.verified_bot_action))) {
      *error =
          "policy.actions: expected allow, challenge, captcha, block, tarpit, "
          "decoy or throttle";
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
                    "rate", "burst", "statuses"},
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
    if (const YAML::Node statuses = item["statuses"]) {
      if (!statuses.IsSequence()) {
        *error = std::format(
            "rate_limits '{}': statuses must be a list like [401, 403]",
            spec.name);
        return false;
      }
      for (const auto& status : statuses) {
        spec.statuses.push_back(status.as<int>());
      }
    }
    config->rate_limits.push_back(std::move(spec));
  }
  RateLimitSet compiled;
  return RateLimitSet::Compile(config->rate_limits, &compiled, error);
}

bool ParseRoot(const YAML::Node& root, Config* config, std::string* error) {
  if (!CheckKeys(root, "",
                 {"listen",
                  "workers",
                  "traefik",
                  "passthrough_hosts",
                  "non_tls",
                  "no_sni",
                  "timeouts",
                  "max_connections",
                  "max_requests_per_connection",
                  "events",
                  "mode",
                  "policy",
                  "rules",
                  "rate_limits",
                  "connection_limits",
                  "docker",
                  "admin",
                  "challenge",
                  "attack",
                  "notify",
                  "crawlers",
                  "behavior",
                  "honeypot",
                  "tarpit",
                  "throttle",
                  "http3",
                  "decoy",
                  "model",
                  "fingerprints",
                  "metrics",
                  "log_level",
                  "web_bot_auth",
                  "asn",
                  "threat_lists",
                  "geoip",
                  "captcha",
                  "xdp",
                  "data_dir",
                  "ca_file",
                  "whoami"},
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
  if (!ReadFallbackRoute(root, "non_tls", &config->non_tls, error) ||
      !ReadFallbackRoute(root, "no_sni", &config->no_sni, error)) {
    return false;
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
  if (root["max_requests_per_connection"]) {
    const auto value = root["max_requests_per_connection"].as<int64_t>();
    if (value <= 0) {
      *error = "max_requests_per_connection: expected a positive number";
      return false;
    }
    config->max_requests_per_connection = static_cast<std::size_t>(value);
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
  if (const YAML::Node throttle = root["throttle"];
      throttle && throttle.IsNull()) {
    config->throttle.reset();  // "throttle: ~" in a layer: no throttle.
  } else if (throttle) {
    if (!CheckKeys(throttle, "throttle", {"rate", "burst", "key"}, error)) {
      return false;
    }
    RateLimitSpec spec;
    spec.name = "throttle";
    spec.key = throttle["key"] ? ReadStrings(throttle["key"])
                               : std::vector<std::string>{"ip_prefix", "ja4"};
    if (!throttle["rate"] || !ParseRate(throttle["rate"].as<std::string>(),
                                        &spec.count, &spec.period)) {
      *error = "throttle: rate must be like 30/m";
      return false;
    }
    spec.burst =
        throttle["burst"] ? throttle["burst"].as<int64_t>() : spec.count;
    RateLimitSet compiled;
    if (!RateLimitSet::Compile({spec}, &compiled, error)) {
      *error = std::format("throttle: {}", *error);
      return false;
    }
    config->throttle = std::move(spec);
  }
  if (const YAML::Node limits = root["connection_limits"]) {
    if (!CheckKeys(
            limits, "connection_limits",
            {"open_per_ip", "new_per_ip", "new_burst_per_ip", "pending_per_ip"},
            error)) {
      return false;
    }
    if (limits["pending_per_ip"]) {
      const auto value = limits["pending_per_ip"].as<int64_t>();
      if (value < 0) {
        *error = "connection_limits.pending_per_ip: expected >= 0";
        return false;
      }
      config->pending_connections_per_ip = static_cast<std::size_t>(value);
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
  if (const YAML::Node behavior = root["behavior"]) {
    if (!CheckKeys(behavior, "behavior", {"enabled", "window", "max_clients"},
                   error) ||
        !ReadDuration(behavior, "behavior", "window", &config->behavior_window,
                      error)) {
      return false;
    }
    if (behavior["enabled"]) {
      config->behavior_enabled = behavior["enabled"].as<bool>();
    }
    if (behavior["max_clients"]) {
      config->behavior_max_clients = behavior["max_clients"].as<std::size_t>();
    }
    if (config->behavior_window < std::chrono::seconds(10)) {
      *error = "behavior.window: expected at least 10s";
      return false;
    }
  }
  if (const YAML::Node honeypot = root["honeypot"]) {
    if (!CheckKeys(honeypot, "honeypot", {"paths", "ttl"}, error) ||
        !ReadDuration(honeypot, "honeypot", "ttl", &config->honeypot_ttl,
                      error)) {
      return false;
    }
    if (const YAML::Node paths = honeypot["paths"]) {
      if (!paths.IsSequence()) {
        *error = "honeypot.paths: expected a list";
        return false;
      }
      config->honeypot_paths = ReadStrings(paths);
      for (const std::string& path : config->honeypot_paths) {
        if (!path.starts_with('/')) {
          *error = std::format("honeypot.paths: '{}' must start with /", path);
          return false;
        }
      }
    }
  }
  if (const YAML::Node http3 = root["http3"]) {
    if (!CheckKeys(http3, "http3",
                   {"enabled", "idle_timeout", "retry", "max_connections",
                    "alt_svc_max_age", "advertise_port"},
                   error) ||
        !ReadDuration(http3, "http3", "idle_timeout",
                      &config->http3_idle_timeout, error) ||
        !ReadDuration(http3, "http3", "alt_svc_max_age",
                      &config->http3_alt_svc_max_age, error)) {
      return false;
    }
    if (http3["enabled"]) config->http3_enabled = http3["enabled"].as<bool>();
    if (http3["retry"]) config->http3_retry = http3["retry"].as<bool>();
    if (http3["max_connections"]) {
      config->http3_max_connections =
          http3["max_connections"].as<std::size_t>();
    }
    if (http3["advertise_port"]) {
      const int port = http3["advertise_port"].as<int>();
      if (port < 0 || port > 65535) {
        *error = "http3.advertise_port: expected 0..65535";
        return false;
      }
      config->http3_advertise_port = static_cast<uint16_t>(port);
    }
    if (config->http3_idle_timeout < std::chrono::seconds(1) ||
        config->http3_idle_timeout > std::chrono::minutes(10)) {
      *error = "http3.idle_timeout: expected 1s..10m";
      return false;
    }
  }
  if (const YAML::Node tarpit = root["tarpit"]) {
    if (!CheckKeys(tarpit, "tarpit",
                   {"duration", "interval", "chunk", "max_active"}, error) ||
        !ReadDuration(tarpit, "tarpit", "duration", &config->tarpit_duration,
                      error) ||
        !ReadDuration(tarpit, "tarpit", "interval", &config->tarpit_interval,
                      error)) {
      return false;
    }
    if (tarpit["chunk"]) {
      config->tarpit_chunk = tarpit["chunk"].as<std::size_t>();
    }
    if (tarpit["max_active"]) {
      config->tarpit_max_active = tarpit["max_active"].as<std::size_t>();
    }
    if (config->tarpit_interval < std::chrono::milliseconds(10) ||
        config->tarpit_duration < config->tarpit_interval ||
        config->tarpit_duration > std::chrono::minutes(10) ||
        config->tarpit_chunk == 0 || config->tarpit_chunk > 65536) {
      *error =
          "tarpit: expected 10ms <= interval <= duration <= 10m and "
          "1 <= chunk <= 65536";
      return false;
    }
  }
  if (const YAML::Node model = root["model"]) {
    if (!CheckKeys(model, "model", {"file", "threshold", "log_features"},
                   error)) {
      return false;
    }
    if (model["file"] && !model["file"].IsNull()) {
      config->model_file = model["file"].as<std::string>();
    }
    if (model["threshold"]) {
      config->model_threshold = model["threshold"].as<double>();
      if (config->model_threshold <= 0 || config->model_threshold >= 1) {
        *error = "model.threshold: expected 0 < threshold < 1";
        return false;
      }
    }
    if (model["log_features"]) {
      config->model_log_features = model["log_features"].as<bool>();
    }
  }
  if (const YAML::Node decoy = root["decoy"]) {
    if (!CheckKeys(decoy, "decoy", {"html_file", "json_file", "labyrinth"},
                   error)) {
      return false;
    }
    if (decoy["labyrinth"]) {
      config->decoy_labyrinth = decoy["labyrinth"].as<bool>();
    }
    struct Template {
      const char* key;
      std::string* path;
      std::string* contents;
    };
    for (const auto& [key, path_out, out] :
         {Template{"html_file", &config->decoy_html_file, &config->decoy_html},
          Template{"json_file", &config->decoy_json_file,
                   &config->decoy_json}}) {
      if (!decoy[key]) continue;
      const auto path =
          decoy[key].IsNull() ? std::string() : decoy[key].as<std::string>();
      *path_out = path;
      out->clear();
      if (path.empty()) continue;  // Built-in template.
      std::ifstream file(path);
      if (!file) {
        *error = std::format("decoy.{}: cannot open {}", key, path);
        return false;
      }
      std::stringstream contents;
      contents << file.rdbuf();
      *out = contents.str();
    }
  }
  if (const YAML::Node crawlers = root["crawlers"]) {
    if (!CheckKeys(crawlers, "crawlers",
                   {"verify", "ai", "ai_robots", "ip_ranges", "ranges_refresh"},
                   error) ||
        !ReadDuration(crawlers, "crawlers", "ranges_refresh",
                      &config->crawlers_ranges_refresh, error)) {
      return false;
    }
    if (crawlers["ip_ranges"]) {
      config->crawlers_ip_ranges = crawlers["ip_ranges"].as<bool>();
    }
    if (crawlers["verify"]) {
      config->crawlers_verify = crawlers["verify"].as<bool>();
    }
    if (crawlers["ai_robots"]) {
      config->crawlers_ai_robots = crawlers["ai_robots"].as<bool>();
    }
    if (crawlers["ai"]) {
      const auto ai = crawlers["ai"].as<std::string>();
      Action action = Action::kAllow;
      if (ai == "default") {
        config->crawlers_ai.reset();
      } else if (ParseAction(ai, &action)) {
        config->crawlers_ai = action;
      } else {
        *error =
            "crawlers.ai: expected default, allow, challenge, captcha, block, "
            "tarpit, decoy or throttle";
        return false;
      }
    }
  }
  if (const YAML::Node challenge = root["challenge"]) {
    if (!CheckKeys(challenge, "challenge",
                   {"keys_file", "token_ttl", "difficulty", "token_credit",
                    "endpoint_rate", "endpoint_burst"},
                   error) ||
        !ReadDuration(challenge, "challenge", "token_ttl",
                      &config->challenge_token_ttl, error)) {
      return false;
    }
    if (challenge["keys_file"] && !challenge["keys_file"].IsNull()) {
      config->challenge_keys_file = challenge["keys_file"].as<std::string>();
    }
    if (const YAML::Node difficulty = challenge["difficulty"]) {
      if (!CheckKeys(difficulty, "challenge.difficulty", {"suspicious", "bot"},
                     error)) {
        return false;
      }
      if (difficulty["suspicious"]) {
        config->challenge_suspicious_difficulty =
            difficulty["suspicious"].as<int>();
      }
      if (difficulty["bot"]) {
        config->challenge_bot_difficulty = difficulty["bot"].as<int>();
      }
      for (const int bits : {config->challenge_suspicious_difficulty,
                             config->challenge_bot_difficulty}) {
        if (bits < 0 || bits > 26) {
          *error = "challenge.difficulty: expected 0..26 bits";
          return false;
        }
      }
    }
    if (challenge["token_credit"]) {
      config->challenge_token_credit = challenge["token_credit"].as<int>();
      if (config->challenge_token_credit < 0 ||
          config->challenge_token_credit > 100) {
        *error = "challenge.token_credit: expected 0..100";
        return false;
      }
    }
    if (challenge["endpoint_rate"] &&
        !ParseRate(challenge["endpoint_rate"].as<std::string>(),
                   &config->challenge_endpoint_rate,
                   &config->challenge_endpoint_period)) {
      *error = "challenge.endpoint_rate: expected a rate like 30/m";
      return false;
    }
    if (challenge["endpoint_burst"]) {
      config->challenge_endpoint_burst =
          challenge["endpoint_burst"].as<int64_t>();
      if (config->challenge_endpoint_burst < 1) {
        *error = "challenge.endpoint_burst: expected >= 1";
        return false;
      }
    }
  }
  if (const YAML::Node attack = root["attack"]) {
    if (!CheckKeys(attack, "attack", {"auto_rps", "auto_duration"}, error) ||
        !ReadDuration(attack, "attack", "auto_duration",
                      &config->attack_auto_duration, error)) {
      return false;
    }
    if (attack["auto_rps"]) {
      config->attack_auto_rps = attack["auto_rps"].as<int64_t>();
      if (config->attack_auto_rps < 0) {
        *error = "attack.auto_rps: expected >= 0 (0 = off)";
        return false;
      }
    }
  }
  if (const YAML::Node notify = root["notify"]) {
    if (!CheckKeys(
            notify, "notify",
            {"name", "webhook", "telegram", "nats_down_after", "repeat_after"},
            error) ||
        !ReadDuration(notify, "notify", "nats_down_after",
                      &config->notify_nats_down_after, error) ||
        !ReadDuration(notify, "notify", "repeat_after",
                      &config->notify_repeat_after, error)) {
      return false;
    }
    const auto text = [](const YAML::Node& node) {
      return !node || node.IsNull() ? std::string() : node.as<std::string>();
    };
    if (notify["name"]) config->notify_name = text(notify["name"]);
    if (notify["webhook"]) {
      config->notify_webhook = text(notify["webhook"]);
      ParsedUrl url;
      if (!config->notify_webhook.empty() &&
          !ParseUrl(config->notify_webhook, &url)) {
        // The URL is a secret (Slack-style webhooks carry a token).
        *error = "notify.webhook: expected an http:// or https:// URL";
        return false;
      }
    }
    if (const YAML::Node telegram = notify["telegram"]) {
      if (!CheckKeys(telegram, "notify.telegram", {"token", "chat_id"},
                     error)) {
        return false;
      }
      if (telegram["token"]) {
        config->notify_telegram_token = text(telegram["token"]);
      }
      if (telegram["chat_id"]) {
        config->notify_telegram_chat_id = text(telegram["chat_id"]);
      }
    }
    if (config->notify_telegram_token.empty() !=
        config->notify_telegram_chat_id.empty()) {
      *error = "notify.telegram: set both token and chat_id, or neither";
      return false;
    }
    if (config->notify_telegram_token.find('/') != std::string::npos) {
      *error = "notify.telegram.token: expected a bot token like 123:ABC";
      return false;
    }
  }
  if (const YAML::Node admin = root["admin"]) {
    if (!CheckKeys(admin, "admin",
                   {"socket", "state_file", "modes_file", "settings_file",
                    "decisions"},
                   error)) {
      return false;
    }
    if (admin["socket"]) {
      config->admin_socket =
          admin["socket"].IsNull() ? "" : admin["socket"].as<std::string>();
    }
    if (admin["state_file"]) {
      config->admin_state_file = admin["state_file"].IsNull()
                                     ? ""
                                     : admin["state_file"].as<std::string>();
    }
    if (admin["modes_file"]) {
      config->admin_modes_file = admin["modes_file"].IsNull()
                                     ? ""
                                     : admin["modes_file"].as<std::string>();
    }
    if (admin["settings_file"]) {
      config->admin_settings_file =
          admin["settings_file"].IsNull()
              ? ""
              : admin["settings_file"].as<std::string>();
    }
    if (admin["decisions"]) {
      const auto value = admin["decisions"].as<int64_t>();
      if (value < 0 || value > 1'000'000) {
        *error = "admin.decisions: expected 0..1000000";
        return false;
      }
      config->admin_decisions = static_cast<std::size_t>(value);
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
  if (const YAML::Node agents = root["web_bot_auth"]) {
    if (!CheckKeys(agents, "web_bot_auth",
                   {"enabled", "trusted", "max_validity"}, error) ||
        !ReadDuration(agents, "web_bot_auth", "max_validity",
                      &config->web_bot_auth_max_validity, error)) {
      return false;
    }
    if (agents["enabled"]) {
      config->web_bot_auth_enabled = agents["enabled"].as<bool>();
    }
    if (const YAML::Node trusted = agents["trusted"]) {
      if (!trusted.IsSequence()) {
        *error = "web_bot_auth.trusted: expected a list of hosts";
        return false;
      }
      config->web_bot_auth_trusted = ReadStrings(trusted);
    }
  }
  if (const YAML::Node geoip = root["geoip"]) {
    if (!CheckKeys(geoip, "geoip", {"url", "refresh"}, error) ||
        !ReadDuration(geoip, "geoip", "refresh", &config->geoip_refresh,
                      error)) {
      return false;
    }
    if (geoip["url"]) {
      config->geoip_url =
          geoip["url"].IsNull() ? "" : geoip["url"].as<std::string>();
      ParsedUrl url;
      if (!config->geoip_url.empty() &&
          !ParseUrl(GeoUrlForMonth(config->geoip_url, 2026, 1), &url)) {
        *error = "geoip.url: expected an http(s) URL or \"\" (off)";
        return false;
      }
    }
  }
  if (const YAML::Node lists = root["threat_lists"]) {
    if (!CheckKeys(lists, "threat_lists", {"enabled", "refresh"}, error) ||
        !ReadDuration(lists, "threat_lists", "refresh",
                      &config->threat_lists_refresh, error)) {
      return false;
    }
    if (lists["enabled"]) {
      config->threat_lists = ReadStrings(lists["enabled"]);
      for (const std::string& id : config->threat_lists) {
        if (FindThreatList(id) == nullptr) {
          std::string known;
          for (const ThreatList& list : KnownThreatLists()) {
            known += known.empty() ? "" : ", ";
            known += list.id;
          }
          *error = std::format("threat_lists.enabled: unknown list '{}' ({})",
                               id, known);
          return false;
        }
      }
    }
  }
  if (const YAML::Node asn = root["asn"]) {
    if (!CheckKeys(asn, "asn", {"url", "refresh"}, error) ||
        !ReadDuration(asn, "asn", "refresh", &config->asn_refresh, error)) {
      return false;
    }
    if (asn["url"]) {
      config->asn_url = asn["url"].IsNull() ? "" : asn["url"].as<std::string>();
      if (!config->asn_url.empty() &&
          !config->asn_url.starts_with("https://") &&
          !config->asn_url.starts_with("http://")) {
        *error = "asn.url: expected an http(s) URL or \"\" (off)";
        return false;
      }
    }
  }
  if (root["data_dir"]) {
    config->data_dir =
        root["data_dir"].IsNull() ? "" : root["data_dir"].as<std::string>();
  }
  if (root["whoami"]) config->whoami = root["whoami"].as<bool>();
  if (root["ca_file"]) {
    config->ca_file =
        root["ca_file"].IsNull() ? "" : root["ca_file"].as<std::string>();
  }
  if (const YAML::Node captcha = root["captcha"]) {
    if (!CheckKeys(captcha, "captcha",
                   {"provider", "site_key", "secret_file", "secret",
                    "verify_url", "check_hostname", "escalate", "rounds",
                    "round_timeout", "difficulty"},
                   error) ||
        !ReadDuration(captcha, "captcha", "round_timeout",
                      &config->captcha_round_timeout, error)) {
      return false;
    }
    const auto text = [&captcha](const char* key) {
      return captcha[key].IsNull() ? std::string()
                                   : captcha[key].as<std::string>();
    };
    if (captcha["provider"]) config->captcha_provider = text("provider");
    if (captcha["site_key"]) config->captcha_site_key = text("site_key");
    if (captcha["secret_file"]) {
      config->captcha_secret_file = text("secret_file");
    }
    if (captcha["secret"]) config->captcha_secret = text("secret");
    if (captcha["verify_url"]) config->captcha_verify_url = text("verify_url");
    if (captcha["check_hostname"]) {
      config->captcha_check_hostname = captcha["check_hostname"].as<bool>();
    }
    if (captcha["escalate"]) {
      config->captcha_escalate = captcha["escalate"].as<bool>();
    }
    if (captcha["rounds"]) {
      config->captcha_rounds = captcha["rounds"].as<int>();
      if (config->captcha_rounds < 1 || config->captcha_rounds > 5) {
        *error = "captcha.rounds: expected 1..5";
        return false;
      }
    }
    if (captcha["difficulty"]) {
      config->captcha_difficulty = captcha["difficulty"].as<int>();
      if (config->captcha_difficulty < 0 || config->captcha_difficulty > 20) {
        *error = "captcha.difficulty: expected 0..20 bits";
        return false;
      }
    }
    const std::string& provider = config->captcha_provider;
    if (!provider.empty() && provider != "builtin" && provider != "turnstile" &&
        provider != "hcaptcha" && provider != "recaptcha") {
      *error =
          "captcha.provider: expected \"\" (off), builtin, turnstile, "
          "hcaptcha or recaptcha";
      return false;
    }
    if (!config->captcha_secret.empty() &&
        !config->captcha_secret_file.empty()) {
      *error = "captcha.secret: set either secret or secret_file, not both";
      return false;
    }
    if (!provider.empty() && provider != "builtin" &&
        (config->captcha_site_key.empty() ||
         (config->captcha_secret_file.empty() &&
          config->captcha_secret.empty()))) {
      *error = std::format(
          "captcha: {} needs site_key and secret_file (or secret)", provider);
      return false;
    }
  }
  if (const YAML::Node xdp = root["xdp"]) {
    if (!CheckKeys(xdp, "xdp",
                   {"enabled", "interface", "mode", "syn_rate", "syn_burst",
                    "drop_invalid", "drop_fragments", "heartbeat_timeout",
                    "block_honeypot"},
                   error) ||
        !ReadDuration(xdp, "xdp", "heartbeat_timeout",
                      &config->xdp_heartbeat_timeout, error)) {
      return false;
    }
    if (xdp["enabled"]) config->xdp_enabled = xdp["enabled"].as<bool>();
    if (xdp["interface"]) {
      config->xdp_interface = xdp["interface"].as<std::string>();
    }
    if (xdp["mode"]) {
      config->xdp_mode = xdp["mode"].as<std::string>();
      if (config->xdp_mode != "auto" && config->xdp_mode != "native" &&
          config->xdp_mode != "generic") {
        *error = "xdp.mode: expected auto, native or generic";
        return false;
      }
    }
    if (xdp["syn_rate"]) {
      const auto rate = xdp["syn_rate"].as<std::string>();
      int64_t count = 0;
      std::chrono::milliseconds period{0};
      if (rate.empty() || rate == "0") {
        config->xdp_syn_rate = 0;
      } else if (!ParseRate(rate, &count, &period) || period.count() > 1000 ||
                 count * 1000 / period.count() < 1) {
        *error = "xdp.syn_rate: expected a rate per second like 200/s";
        return false;
      } else {
        config->xdp_syn_rate = count * 1000 / period.count();
      }
    }
    if (xdp["syn_burst"]) {
      config->xdp_syn_burst = xdp["syn_burst"].as<int64_t>();
      if (config->xdp_syn_burst < 1) {
        *error = "xdp.syn_burst: expected >= 1";
        return false;
      }
    }
    if (xdp["drop_invalid"]) {
      config->xdp_drop_invalid = xdp["drop_invalid"].as<bool>();
    }
    if (xdp["drop_fragments"]) {
      config->xdp_drop_fragments = xdp["drop_fragments"].as<bool>();
    }
    if (xdp["block_honeypot"]) {
      config->xdp_block_honeypot = xdp["block_honeypot"].as<bool>();
    }
    if (config->xdp_enabled && config->xdp_interface.empty()) {
      *error = "xdp.interface: required when xdp.enabled (e.g. eth0)";
      return false;
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
