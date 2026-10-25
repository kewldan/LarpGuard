#include "config/settings.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <initializer_list>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/log.h"
#include "config/config.h"
#include "ratelimit/limits.h"
#include "score/policy.h"
#include "score/rules.h"

namespace bot_shield {
namespace {

using Json = nlohmann::json;
using std::chrono::milliseconds;

constexpr std::string_view kModes[] = {"shadow", "enforce"};
constexpr std::string_view kFallbackRoutes[] = {"reject", "passthrough"};
constexpr std::string_view kActions[] = {
    "allow", "challenge", "captcha", "block", "tarpit", "decoy", "throttle"};
constexpr std::string_view kAiActions[] = {"default", "allow",   "challenge",
                                           "captcha", "block",   "tarpit",
                                           "decoy",   "throttle"};
constexpr std::string_view kCaptchaProviders[] = {"", "builtin", "turnstile",
                                                  "hcaptcha", "recaptcha"};
constexpr std::string_view kXdpModes[] = {"auto", "native", "generic"};
constexpr std::string_view kLogLevels[] = {"debug", "info", "warn", "error"};

Json Duration(milliseconds duration) { return FormatDuration(duration); }

Json OptionalEndpoint(const std::optional<Endpoint>& endpoint) {
  return endpoint ? endpoint->ToString() : std::string();
}

std::string_view FallbackName(FallbackRoute route) {
  return route == FallbackRoute::kReject ? "reject" : "passthrough";
}

std::string_view LevelName(log::Level level) {
  switch (level) {
    case log::Level::kDebug:
      return "debug";
    case log::Level::kInfo:
      return "info";
    case log::Level::kWarn:
      return "warn";
    case log::Level::kError:
      return "error";
  }
  return "info";
}

Json HostModes(const std::vector<std::pair<std::string, HostMode>>& modes) {
  Json out = Json::object();
  for (const auto& [host, mode] : modes) out[host] = HostModeName(mode);
  return out;
}

Json Rules(const std::vector<RuleSpec>& rules) {
  Json out = Json::array();
  for (const RuleSpec& rule : rules) {
    Json json = {
        {"name", rule.name}, {"when", rule.when}, {"action", rule.action}};
    if (rule.action == "score") json["score"] = rule.score;
    out.push_back(std::move(json));
  }
  return out;
}

Json RateLimits(const std::vector<RateLimitSpec>& limits) {
  Json out = Json::array();
  for (const RateLimitSpec& spec : limits) {
    Json limit = {{"name", spec.name},
                  {"hosts", spec.hosts},
                  {"paths", spec.paths},
                  {"methods", spec.methods},
                  {"classes", spec.classes},
                  {"key", spec.key},
                  {"rate", FormatRate(spec.count, spec.period)},
                  {"burst", spec.burst}};
    // Only when set: limits written before statuses existed stay as they
    // are.
    if (!spec.statuses.empty()) limit["statuses"] = spec.statuses;
    out.push_back(std::move(limit));
  }
  return out;
}

Json Throttle(const std::optional<RateLimitSpec>& throttle) {
  if (!throttle) return nullptr;
  return {{"rate", FormatRate(throttle->count, throttle->period)},
          {"burst", throttle->burst},
          {"key", throttle->key}};
}

using T = SettingType;
using A = SettingApply;
using C = const Config&;

using Getter = Json (*)(const Config&);

constexpr SettingKey Live(std::string_view path, SettingType type, Getter get) {
  return {path, type, SettingApply::kLive, false, {}, get};
}

constexpr SettingKey Restart(std::string_view path, SettingType type,
                             Getter get) {
  return {path, type, SettingApply::kRestart, false, {}, get};
}

constexpr SettingKey Yaml(std::string_view path, SettingType type, Getter get) {
  return {path, type, SettingApply::kYaml, false, {}, get};
}

// Secrets are strings read at startup.
constexpr SettingKey Secret(std::string_view path, Getter get) {
  return {path, SettingType::kString, SettingApply::kRestart, true, {}, get};
}

// Secrets that also say where the gateway sends things: main file only.
constexpr SettingKey YamlSecret(std::string_view path, Getter get) {
  return {path, SettingType::kString, SettingApply::kYaml, true, {}, get};
}

constexpr SettingKey Enum(SettingApply apply, std::string_view path,
                          std::span<const std::string_view> options,
                          Getter get) {
  return {path, SettingType::kEnum, apply, false, options, get};
}

// In the order of deploy/bot-shield.yaml.
constexpr SettingKey kKeys[] = {
    Yaml("listen.https", T::kEndpoint,
         [](C c) -> Json { return c.listen_https.ToString(); }),
    Yaml("listen.http", T::kEndpoint,
         [](C c) { return OptionalEndpoint(c.listen_http); }),
    Restart("workers", T::kInt, [](C c) -> Json { return c.workers; }),
    Yaml("traefik.acme_json", T::kString,
         [](C c) -> Json { return c.acme_json; }),
    Restart("traefik.acme_reload_interval", T::kDuration,
            [](C c) { return Duration(c.acme_reload_interval); }),
    Yaml("traefik.upstream_https", T::kEndpoint,
         [](C c) -> Json { return c.upstream_https.ToString(); }),
    Yaml("traefik.upstream_http", T::kEndpoint,
         [](C c) -> Json { return c.upstream_http.ToString(); }),
    Restart("traefik.proxy_protocol", T::kBool,
            [](C c) -> Json { return c.proxy_protocol; }),
    Restart("traefik.pool_size", T::kInt,
            [](C c) -> Json { return c.upstream_pool_size; }),
    Restart("traefik.tls_verify", T::kBool,
            [](C c) -> Json { return c.upstream_tls_verify; }),
    Restart("passthrough_hosts", T::kStrings,
            [](C c) -> Json { return c.passthrough_hosts; }),
    Enum(A::kRestart, "non_tls", kFallbackRoutes,
         [](C c) -> Json { return FallbackName(c.non_tls); }),
    Enum(A::kRestart, "no_sni", kFallbackRoutes,
         [](C c) -> Json { return FallbackName(c.no_sni); }),
    Restart("timeouts.client_hello", T::kDuration,
            [](C c) { return Duration(c.client_hello_timeout); }),
    Restart("timeouts.tls_handshake", T::kDuration,
            [](C c) { return Duration(c.tls_handshake_timeout); }),
    Restart("timeouts.request_headers", T::kDuration,
            [](C c) { return Duration(c.request_headers_timeout); }),
    Restart("timeouts.upstream_connect", T::kDuration,
            [](C c) { return Duration(c.upstream_connect_timeout); }),
    Restart("timeouts.idle", T::kDuration,
            [](C c) { return Duration(c.idle_timeout); }),
    Restart("timeouts.drain", T::kDuration,
            [](C c) { return Duration(c.drain_timeout); }),
    Restart("timeouts.upstream_idle", T::kDuration,
            [](C c) { return Duration(c.upstream_idle_timeout); }),
    Restart("max_connections", T::kInt,
            [](C c) -> Json { return c.max_connections; }),
    Restart("max_requests_per_connection", T::kInt,
            [](C c) -> Json { return c.max_requests_per_connection; }),
    Yaml("events.nats", T::kEndpoint,
         [](C c) { return OptionalEndpoint(c.events_nats); }),
    Restart("events.subject_prefix", T::kString,
            [](C c) -> Json { return c.events_subject_prefix; }),
    Secret("events.token", [](C c) -> Json { return c.events_token; }),
    Restart("events.user", T::kString,
            [](C c) -> Json { return c.events_user; }),
    Secret("events.password", [](C c) -> Json { return c.events_password; }),
    Restart("events.max_queue", T::kInt,
            [](C c) -> Json { return c.events_max_queue; }),
    Secret("events.ip_salt", [](C c) -> Json { return c.events_ip_salt; }),
    Restart("events.requests", T::kBool,
            [](C c) -> Json { return c.events_requests; }),
    Enum(A::kLive, "mode", kModes,
         [](C c) -> Json { return c.policy.enforce ? "enforce" : "shadow"; }),
    Live("policy.thresholds.suspicious", T::kInt,
         [](C c) -> Json { return c.policy.suspicious_threshold; }),
    Live("policy.thresholds.bot", T::kInt,
         [](C c) -> Json { return c.policy.bot_threshold; }),
    Enum(A::kLive, "policy.actions.suspicious", kActions,
         [](C c) -> Json { return ActionName(c.policy.suspicious_action); }),
    Enum(A::kLive, "policy.actions.bot", kActions,
         [](C c) -> Json { return ActionName(c.policy.bot_action); }),
    Enum(A::kLive, "policy.actions.verified_bot", kActions,
         [](C c) -> Json { return ActionName(c.policy.verified_bot_action); }),
    Live("policy.block_status", T::kInt,
         [](C c) -> Json { return c.policy.block_status; }),
    Live("policy.hosts", T::kHostModes,
         [](C c) { return HostModes(c.policy.host_modes); }),
    Live("rules", T::kRules, [](C c) { return Rules(c.rules); }),
    Live("rate_limits", T::kRateLimits,
         [](C c) { return RateLimits(c.rate_limits); }),
    Restart("connection_limits.open_per_ip", T::kInt,
            [](C c) -> Json { return c.open_connections_per_ip; }),
    Restart("connection_limits.new_per_ip", T::kRate,
            [](C c) -> Json {
              return c.new_connections_per_ip == 0
                         ? std::string()
                         : FormatRate(c.new_connections_per_ip,
                                      c.new_connections_period);
            }),
    Restart("connection_limits.new_burst_per_ip", T::kInt,
            [](C c) -> Json { return c.new_connections_burst; }),
    Restart("connection_limits.pending_per_ip", T::kInt,
            [](C c) -> Json { return c.pending_connections_per_ip; }),
    Yaml("docker.socket", T::kString,
         [](C c) -> Json { return c.docker_socket; }),
    Restart("docker.poll_interval", T::kDuration,
            [](C c) { return Duration(c.docker_poll_interval); }),
    Restart("behavior.enabled", T::kBool,
            [](C c) -> Json { return c.behavior_enabled; }),
    Restart("behavior.window", T::kDuration,
            [](C c) { return Duration(c.behavior_window); }),
    Restart("behavior.max_clients", T::kInt,
            [](C c) -> Json { return c.behavior_max_clients; }),
    Live("honeypot.paths", T::kStrings,
         [](C c) -> Json { return c.honeypot_paths; }),
    Restart("honeypot.ttl", T::kDuration,
            [](C c) { return Duration(c.honeypot_ttl); }),
    Live("throttle", T::kThrottle, [](C c) { return Throttle(c.throttle); }),
    Restart("tarpit.duration", T::kDuration,
            [](C c) { return Duration(c.tarpit_duration); }),
    Restart("tarpit.interval", T::kDuration,
            [](C c) { return Duration(c.tarpit_interval); }),
    Restart("tarpit.chunk", T::kInt,
            [](C c) -> Json { return c.tarpit_chunk; }),
    Restart("tarpit.max_active", T::kInt,
            [](C c) -> Json { return c.tarpit_max_active; }),
    Yaml("decoy.html_file", T::kString,
         [](C c) -> Json { return c.decoy_html_file; }),
    Yaml("decoy.json_file", T::kString,
         [](C c) -> Json { return c.decoy_json_file; }),
    Restart("decoy.labyrinth", T::kBool,
            [](C c) -> Json { return c.decoy_labyrinth; }),
    Restart("http3.enabled", T::kBool,
            [](C c) -> Json { return c.http3_enabled; }),
    Restart("http3.idle_timeout", T::kDuration,
            [](C c) { return Duration(c.http3_idle_timeout); }),
    Restart("http3.retry", T::kBool, [](C c) -> Json { return c.http3_retry; }),
    Restart("http3.max_connections", T::kInt,
            [](C c) -> Json { return c.http3_max_connections; }),
    Restart("http3.alt_svc_max_age", T::kDuration,
            [](C c) { return Duration(c.http3_alt_svc_max_age); }),
    Restart("http3.advertise_port", T::kInt,
            [](C c) -> Json { return c.http3_advertise_port; }),
    Yaml("model.file", T::kString, [](C c) -> Json { return c.model_file; }),
    Live("model.threshold", T::kNumber,
         [](C c) -> Json { return c.model_threshold; }),
    Restart("model.log_features", T::kBool,
            [](C c) -> Json { return c.model_log_features; }),
    Restart("crawlers.verify", T::kBool,
            [](C c) -> Json { return c.crawlers_verify; }),
    Enum(A::kLive, "crawlers.ai", kAiActions,
         [](C c) -> Json {
           return c.crawlers_ai ? ActionName(*c.crawlers_ai) : "default";
         }),
    Live("crawlers.ai_robots", T::kBool,
         [](C c) -> Json { return c.crawlers_ai_robots; }),
    Restart("crawlers.ip_ranges", T::kBool,
            [](C c) -> Json { return c.crawlers_ip_ranges; }),
    Restart("crawlers.ranges_refresh", T::kDuration,
            [](C c) { return Duration(c.crawlers_ranges_refresh); }),
    Restart("web_bot_auth.enabled", T::kBool,
            [](C c) -> Json { return c.web_bot_auth_enabled; }),
    Live("web_bot_auth.trusted", T::kStrings,
         [](C c) -> Json { return c.web_bot_auth_trusted; }),
    Restart("web_bot_auth.max_validity", T::kDuration,
            [](C c) { return Duration(c.web_bot_auth_max_validity); }),
    Restart("asn.url", T::kString, [](C c) -> Json { return c.asn_url; }),
    Restart("asn.refresh", T::kDuration,
            [](C c) { return Duration(c.asn_refresh); }),
    Yaml("data_dir", T::kString, [](C c) -> Json { return c.data_dir; }),
    Yaml("ca_file", T::kString, [](C c) -> Json { return c.ca_file; }),
    Enum(A::kRestart, "captcha.provider", kCaptchaProviders,
         [](C c) -> Json { return c.captcha_provider; }),
    Restart("captcha.site_key", T::kString,
            [](C c) -> Json { return c.captcha_site_key; }),
    Yaml("captcha.secret_file", T::kString,
         [](C c) -> Json { return c.captcha_secret_file; }),
    Secret("captcha.secret", [](C c) -> Json { return c.captcha_secret; }),
    Yaml("captcha.verify_url", T::kString,
         [](C c) -> Json { return c.captcha_verify_url; }),
    Restart("captcha.check_hostname", T::kBool,
            [](C c) -> Json { return c.captcha_check_hostname; }),
    Restart("captcha.escalate", T::kBool,
            [](C c) -> Json { return c.captcha_escalate; }),
    Restart("captcha.rounds", T::kInt,
            [](C c) -> Json { return c.captcha_rounds; }),
    Restart("captcha.round_timeout", T::kDuration,
            [](C c) { return Duration(c.captcha_round_timeout); }),
    Restart("captcha.difficulty", T::kInt,
            [](C c) -> Json { return c.captcha_difficulty; }),
    Restart("xdp.enabled", T::kBool, [](C c) -> Json { return c.xdp_enabled; }),
    Restart("xdp.interface", T::kString,
            [](C c) -> Json { return c.xdp_interface; }),
    Enum(A::kRestart, "xdp.mode", kXdpModes,
         [](C c) -> Json { return c.xdp_mode; }),
    Restart("xdp.syn_rate", T::kRate,
            [](C c) -> Json {
              return c.xdp_syn_rate == 0 ? std::string()
                                         : std::format("{}/s", c.xdp_syn_rate);
            }),
    Restart("xdp.syn_burst", T::kInt,
            [](C c) -> Json { return c.xdp_syn_burst; }),
    Restart("xdp.drop_invalid", T::kBool,
            [](C c) -> Json { return c.xdp_drop_invalid; }),
    Restart("xdp.drop_fragments", T::kBool,
            [](C c) -> Json { return c.xdp_drop_fragments; }),
    Restart("xdp.heartbeat_timeout", T::kDuration,
            [](C c) { return Duration(c.xdp_heartbeat_timeout); }),
    Restart("xdp.block_honeypot", T::kBool,
            [](C c) -> Json { return c.xdp_block_honeypot; }),
    Yaml("challenge.keys_file", T::kString,
         [](C c) -> Json { return c.challenge_keys_file; }),
    Restart("challenge.token_ttl", T::kDuration,
            [](C c) { return Duration(c.challenge_token_ttl); }),
    Restart("challenge.difficulty.suspicious", T::kInt,
            [](C c) -> Json { return c.challenge_suspicious_difficulty; }),
    Restart("challenge.difficulty.bot", T::kInt,
            [](C c) -> Json { return c.challenge_bot_difficulty; }),
    Restart("challenge.token_credit", T::kInt,
            [](C c) -> Json { return c.challenge_token_credit; }),
    Restart("challenge.endpoint_rate", T::kRate,
            [](C c) -> Json {
              return FormatRate(c.challenge_endpoint_rate,
                                c.challenge_endpoint_period);
            }),
    Restart("challenge.endpoint_burst", T::kInt,
            [](C c) -> Json { return c.challenge_endpoint_burst; }),
    Restart("attack.auto_rps", T::kInt,
            [](C c) -> Json { return c.attack_auto_rps; }),
    Restart("attack.auto_duration", T::kDuration,
            [](C c) { return Duration(c.attack_auto_duration); }),
    Restart("notify.name", T::kString,
            [](C c) -> Json { return c.notify_name; }),
    YamlSecret("notify.webhook", [](C c) -> Json { return c.notify_webhook; }),
    YamlSecret("notify.telegram.token",
               [](C c) -> Json { return c.notify_telegram_token; }),
    Yaml("notify.telegram.chat_id", T::kString,
         [](C c) -> Json { return c.notify_telegram_chat_id; }),
    Restart("notify.nats_down_after", T::kDuration,
            [](C c) { return Duration(c.notify_nats_down_after); }),
    Restart("notify.repeat_after", T::kDuration,
            [](C c) { return Duration(c.notify_repeat_after); }),
    Yaml("admin.socket", T::kString,
         [](C c) -> Json { return c.admin_socket; }),
    Yaml("admin.state_file", T::kString,
         [](C c) -> Json { return c.admin_state_file; }),
    Yaml("admin.modes_file", T::kString,
         [](C c) -> Json { return c.admin_modes_file; }),
    Yaml("admin.settings_file", T::kString,
         [](C c) -> Json { return c.admin_settings_file; }),
    Restart("admin.decisions", T::kInt,
            [](C c) -> Json { return c.admin_decisions; }),
    Yaml("fingerprints.library", T::kString,
         [](C c) -> Json { return c.fingerprint_library; }),
    Yaml("metrics.listen", T::kEndpoint,
         [](C c) { return OptionalEndpoint(c.metrics_listen); }),
    Enum(A::kRestart, "log_level", kLogLevels,
         [](C c) -> Json { return LevelName(c.log_level); }),
    Restart("whoami", T::kBool, [](C c) -> Json { return c.whoami; }),
};

bool ParseInt(std::string_view text, int64_t* value) {
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* begin = text.data();
  const char* end = begin + text.size();
  const auto [ptr, ec] = std::from_chars(begin, end, *value);
  return ec == std::errc() && ptr == end && !text.empty();
}

bool ParseDouble(std::string_view text, double* value) {
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* begin = text.data();
  const char* end = begin + text.size();
  const auto [ptr, ec] = std::from_chars(begin, end, *value);
  return ec == std::errc() && ptr == end && !text.empty();
}

Json FromYaml(const YAML::Node& node) {
  switch (node.Type()) {
    case YAML::NodeType::Map: {
      Json out = Json::object();
      for (const auto& item : node) {
        out[item.first.as<std::string>()] = FromYaml(item.second);
      }
      return out;
    }
    case YAML::NodeType::Sequence: {
      Json out = Json::array();
      for (const auto& item : node) out.push_back(FromYaml(item));
      return out;
    }
    case YAML::NodeType::Scalar: {
      const auto& text = node.Scalar();
      if (node.Tag() == "!") return text;  // Quoted: always a string.
      if (text == "true" || text == "false") return text == "true";
      if (int64_t value = 0; ParseInt(text, &value)) return value;
      if (double value = 0; ParseDouble(text, &value)) return value;
      return text;
    }
    case YAML::NodeType::Null:
    case YAML::NodeType::Undefined:
      return nullptr;
  }
  return nullptr;
}

void Emit(YAML::Emitter& out, const Json& value) {
  if (value.is_object()) {
    out << YAML::BeginMap;
    for (const auto& [key, item] : value.items()) {
      out << YAML::Key << key << YAML::Value;
      Emit(out, item);
    }
    out << YAML::EndMap;
  } else if (value.is_array()) {
    const bool flat = std::ranges::all_of(
        value, [](const Json& item) { return item.is_primitive(); });
    out << (flat ? YAML::Flow : YAML::Block) << YAML::BeginSeq;
    for (const Json& item : value) Emit(out, item);
    out << YAML::EndSeq;
  } else if (value.is_string()) {
    out << YAML::DoubleQuoted << value.get<std::string>();
  } else if (value.is_boolean()) {
    out << (value.get<bool>() ? "true" : "false");
  } else if (value.is_number_integer()) {
    out << value.get<int64_t>();
  } else if (value.is_number()) {
    // Shortest text that reads back as the same double ("0.8").
    out << std::format("{}", value.get<double>());
  } else {
    out << YAML::Null;
  }
}

bool CollectKeys(const Json& node, const std::string& prefix,
                 std::vector<std::string>* paths, std::string* error) {
  for (const auto& [key, value] : node.items()) {
    const std::string path =
        prefix.empty() ? key : std::format("{}.{}", prefix, key);
    if (FindSettingKey(path) != nullptr) {
      paths->push_back(path);
    } else if (value.is_object()) {
      if (!CollectKeys(value, path, paths, error)) return false;
    } else {
      *error = std::format("unknown key '{}'", path);
      return false;
    }
  }
  return true;
}

bool IsStringArray(const Json& value) {
  return value.is_array() && std::ranges::all_of(value, [](const Json& item) {
           return item.is_string();
         });
}

// Fields of an object value: each name in `strings` must be a string, in
// `lists` a list of strings, in `integers` an integer.
bool CheckFields(const Json& value,
                 std::initializer_list<std::string_view> strings,
                 std::initializer_list<std::string_view> lists,
                 std::initializer_list<std::string_view> integers) {
  if (!value.is_object()) return false;
  for (const auto& [key, item] : value.items()) {
    if (std::ranges::find(strings, key) != strings.end()) {
      if (!item.is_string()) return false;
    } else if (std::ranges::find(lists, key) != lists.end()) {
      if (!IsStringArray(item)) return false;
    } else if (std::ranges::find(integers, key) != integers.end()) {
      if (!item.is_number_integer()) return false;
    } else {
      return false;
    }
  }
  return true;
}

}  // namespace

std::span<const SettingKey> SettingKeys() { return kKeys; }

const SettingKey* FindSettingKey(std::string_view path) {
  const auto it = std::ranges::find(kKeys, path, &SettingKey::path);
  return it == std::end(kKeys) ? nullptr : &*it;
}

std::string_view SettingTypeName(SettingType type) {
  switch (type) {
    case T::kBool:
      return "bool";
    case T::kInt:
      return "int";
    case T::kNumber:
      return "number";
    case T::kString:
      return "string";
    case T::kDuration:
      return "duration";
    case T::kRate:
      return "rate";
    case T::kEndpoint:
      return "endpoint";
    case T::kEnum:
      return "enum";
    case T::kStrings:
      return "strings";
    case T::kHostModes:
      return "host_modes";
    case T::kRules:
      return "rules";
    case T::kRateLimits:
      return "rate_limits";
    case T::kThrottle:
      return "throttle";
  }
  return "string";
}

std::string_view SettingApplyName(SettingApply apply) {
  switch (apply) {
    case A::kLive:
      return "live";
    case A::kRestart:
      return "restart";
    case A::kYaml:
      return "yaml";
  }
  return "yaml";
}

std::string FormatDuration(milliseconds duration) {
  const int64_t ms = duration.count();
  constexpr int64_t kSecond = 1000;
  constexpr int64_t kMinute = 60 * kSecond;
  constexpr int64_t kHour = 60 * kMinute;
  if (ms != 0 && ms % kHour == 0) return std::format("{}h", ms / kHour);
  if (ms != 0 && ms % kMinute == 0) return std::format("{}m", ms / kMinute);
  if (ms % kSecond == 0) return std::format("{}s", ms / kSecond);
  return std::format("{}ms", ms);
}

std::string FormatRate(int64_t count, milliseconds period) {
  if (period == std::chrono::hours(24)) return std::format("{}/d", count);
  if (period == std::chrono::hours(1)) return std::format("{}/h", count);
  if (period == std::chrono::minutes(1)) return std::format("{}/m", count);
  return std::format("{}/s", count);
}

bool ParseSettingsLayer(std::string_view yaml, Json* layer,
                        std::string* error) {
  try {
    const YAML::Node root = YAML::Load(std::string(yaml));
    if (root.IsNull()) {
      *layer = Json::object();
      return true;
    }
    if (!root.IsMap()) {
      *error = "expected a mapping";
      return false;
    }
    *layer = FromYaml(root);
    return true;
  } catch (const YAML::Exception& e) {
    *error = e.what();
    return false;
  }
}

std::string EmitSettingsLayer(const Json& layer, std::string_view header) {
  std::string out(header);
  if (layer.empty()) return out;
  YAML::Emitter emitter;
  Emit(emitter, layer);
  out += emitter.c_str();
  out += '\n';
  return out;
}

bool SettingsLayerKeys(const Json& layer, std::vector<const SettingKey*>* keys,
                       std::string* error) {
  if (!layer.is_object()) {
    *error = "expected a mapping";
    return false;
  }
  std::vector<std::string> paths;
  if (!CollectKeys(layer, "", &paths, error)) return false;
  keys->clear();
  for (const SettingKey& key : kKeys) {
    if (std::ranges::find(paths, key.path) == paths.end()) continue;
    if (key.apply == A::kYaml) {
      *error = std::format("{}: can only be set in the main file", key.path);
      return false;
    }
    keys->push_back(&key);
  }
  return true;
}

const Json* LayerValue(const Json& layer, std::string_view path) {
  const Json* node = &layer;
  std::size_t start = 0;
  while (true) {
    const std::size_t dot = path.find('.', start);
    const std::string part(path.substr(start, dot - start));
    if (!node->is_object()) return nullptr;
    const auto it = node->find(part);
    if (it == node->end()) return nullptr;
    node = &*it;
    if (dot == std::string_view::npos) return node;
    start = dot + 1;
  }
}

void SetLayerValue(Json* layer, std::string_view path, Json value) {
  Json* node = layer;
  std::size_t start = 0;
  while (true) {
    const std::size_t dot = path.find('.', start);
    const std::string part(path.substr(start, dot - start));
    if (!node->is_object()) *node = Json::object();
    if (dot == std::string_view::npos) {
      (*node)[part] = std::move(value);
      return;
    }
    node = &(*node)[part];
    start = dot + 1;
  }
}

void RemoveLayerValue(Json* layer, std::string_view path) {
  const std::size_t dot = path.find('.');
  const std::string part(path.substr(0, dot));
  if (!layer->is_object() || !layer->contains(part)) return;
  if (dot == std::string_view::npos) {
    layer->erase(part);
    return;
  }
  Json& child = (*layer)[part];
  RemoveLayerValue(&child, path.substr(dot + 1));
  if (child.is_object() && child.empty()) layer->erase(part);
}

bool CheckSettingValue(const SettingKey& key, const Json& value,
                       std::string* error) {
  bool ok = false;
  std::string_view expected;
  switch (key.type) {
    case T::kBool:
      ok = value.is_boolean();
      expected = "true or false";
      break;
    case T::kInt:
      ok = value.is_number_integer();
      expected = "an integer";
      break;
    case T::kNumber:
      ok = value.is_number();
      expected = "a number";
      break;
    case T::kString:
    case T::kDuration:
    case T::kRate:
    case T::kEndpoint:
      ok = value.is_string();
      expected = "a string";
      break;
    case T::kEnum:
      ok = value.is_string() &&
           std::ranges::find(key.options, value.get<std::string>()) !=
               key.options.end();
      expected = "one of the listed values";
      break;
    case T::kStrings:
      ok = IsStringArray(value);
      expected = "a list of strings";
      break;
    case T::kHostModes:
      ok = value.is_object() &&
           std::ranges::all_of(
               value, [](const Json& item) { return item.is_string(); });
      expected = "host: mode pairs";
      break;
    case T::kRules:
      ok =
          value.is_array() && std::ranges::all_of(value, [](const Json& rule) {
            return CheckFields(rule, {"name", "when", "action"}, {}, {"score"});
          });
      expected = "a list of {name, when, action, score}";
      break;
    case T::kRateLimits:
      ok =
          value.is_array() && std::ranges::all_of(value, [](const Json& limit) {
            if (!limit.is_object()) return false;
            Json rest = limit;
            if (const auto it = rest.find("statuses"); it != rest.end()) {
              const bool integers =
                  it->is_array() &&
                  std::ranges::all_of(*it, [](const Json& status) {
                    return status.is_number_integer();
                  });
              if (!integers) return false;
              rest.erase(it);
            }
            return CheckFields(rest, {"name", "rate"},
                               {"hosts", "paths", "methods", "classes", "key"},
                               {"burst"});
          });
      expected = "a list of rate limits";
      break;
    case T::kThrottle:
      ok = value.is_null() || CheckFields(value, {"rate"}, {"key"}, {"burst"});
      expected = "{rate, burst, key} or null";
      break;
  }
  if (!ok) *error = std::format("{}: expected {}", key.path, expected);
  return ok;
}

}  // namespace bot_shield
