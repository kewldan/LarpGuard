#include "admin/server.h"

#include <fcntl.h>  // IWYU pragma: keep (S_IRUSR on Linux)
#include <sys/stat.h>

#include <algorithm>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <format>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/modes.h"
#include "admin/settings.h"
#include "admin/settings_api.h"
#include "common/host.h"
#include "common/log.h"
#include "common/metrics.h"
#include "common/url.h"
#include "common/version.h"
#include "config/config.h"
#include "crawler/crawlers.h"
#include "docker/labels.h"
#include "events/events.h"
#include "fp/http_request.h"
#include "fp/library.h"
#include "fp/user_agent.h"
#include "net/asn.h"
#include "net/watchdog.h"
#include "proxy/http_message.h"
#include "ratelimit/limits.h"
#include "score/policy.h"
#include "score/rules.h"
#include "server/verdicts.h"

namespace bot_shield {
namespace {

using asio::local::stream_protocol;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kMaxHead = std::size_t{64} * 1024;
// POST /rules/test carries up to kMaxSamples events.
constexpr std::size_t kMaxBody = std::size_t{8} * 1024 * 1024;
constexpr std::size_t kMaxSamples = 5000;
constexpr std::size_t kMaxAsns = 200;
constexpr auto kRequestTimeout = std::chrono::seconds(10);

AdminResponse Error(int status, std::string_view message) {
  return {status, {{"error", message}}};
}

AdminResponse Status(const AdminContext& context, int64_t now_seconds) {
  const Metrics& metrics = GlobalMetrics();
  const auto labels =
      context.labels != nullptr ? context.labels->snapshot() : nullptr;
  return {
      200,
      {{"version", kVersion},
       {"uptime_s", now_seconds - context.started_ms / 1000},
       {"mode", context.verdicts->snapshot()->policy->global_enforce()
                    ? "enforce"
                    : "shadow"},
       {"verdicts_generation", context.verdicts->snapshot()->generation},
       {"workers", context.workers},
       {"certificates", context.certificates->snapshot()->certificate_count()},
       {"label_hosts", labels ? labels->host_count() : 0},
       {"connections_active", metrics.connections_active.Get()},
       {"rate_limit_keys", context.rate_limit_store->size()},
       {"list_entries", context.lists->Entries(now_seconds).size()},
       {"attack_entries", context.attack != nullptr
                              ? context.attack->Entries(now_seconds).size()
                              : 0},
       {"nats_connected", metrics.nats_connected.Get() == 1},
       {"events_published", metrics.events_published.Get()},
       {"events_dropped", metrics.events_dropped.Get()},
       {"settings_error",
        context.settings != nullptr && !context.settings->load_error().empty()
            ? nlohmann::json(context.settings->load_error())
            : nlohmann::json(nullptr)}}};
}

AdminResponse HostPolicy(const AdminContext& context,
                         const std::string& raw_host) {
  const std::string host = NormalizeHost(raw_host);
  if (host.empty()) return Error(400, "host parameter is required");
  const auto labels =
      context.labels != nullptr ? context.labels->snapshot() : nullptr;
  const auto verdicts = context.verdicts->snapshot();
  const ModeResolution mode = verdicts->policy->ResolveMode(
      host, labels ? labels->ModeFor(host) : std::nullopt);
  const bool passthrough_config = std::ranges::any_of(
      context.config->passthrough_hosts,
      [&](const std::string& pattern) { return HostMatches(pattern, host); });
  const bool passthrough_labels = labels && labels->IsPassthrough(host);
  std::vector<std::string> limits = verdicts->rate_limits.NamesForHost(host);
  if (labels) {
    for (std::string& name : labels->rate_limits().NamesForHost(host)) {
      limits.push_back(std::move(name));
    }
  }
  const bool certificate =
      context.certificates->snapshot()->Find(host) != nullptr;
  std::string route = "terminate";
  if (passthrough_config || passthrough_labels) {
    route = "passthrough (policy)";
  } else if (!certificate) {
    route = "passthrough (no certificate)";
  }
  return {200,
          {{"host", host},
           {"mode", HostModeName(mode.mode)},
           {"mode_source", mode.source},
           {"route", route},
           {"certificate", certificate},
           {"rate_limits", limits}}};
}

nlohmann::json ModesJson(
    const std::vector<std::pair<std::string, HostMode>>& modes) {
  nlohmann::json json = nlohmann::json::array();
  for (const auto& [host, mode] : modes) {
    json.push_back({{"host", host}, {"mode", HostModeName(mode)}});
  }
  return json;
}

// GET /policy without a host: every host with a mode of its own, by source.
AdminResponse PolicyOverview(const AdminContext& context) {
  const auto verdicts = context.verdicts->snapshot();
  const PolicySettings& settings = verdicts->policy->settings();
  nlohmann::json labels = nlohmann::json::array();
  if (const auto snapshot =
          context.labels != nullptr ? context.labels->snapshot() : nullptr) {
    for (const LabelHostPolicy& host : snapshot->hosts()) {
      nlohmann::json entry = {{"host", host.host},
                              {"container", host.container},
                              {"passthrough", host.passthrough}};
      if (host.mode) entry["mode"] = HostModeName(*host.mode);
      labels.push_back(std::move(entry));
    }
  }
  return {200,
          {{"default", settings.enforce ? "enforce" : "shadow"},
           {"console", ModesJson(settings.console_modes)},
           {"policy_hosts", ModesJson(settings.host_modes)},
           {"labels", labels},
           {"passthrough_hosts", context.config->passthrough_hosts}}};
}

// POST /policy {"host": "<host>|*.<parent>", "mode": "shadow|enforce|off"}
// and DELETE /policy/<host>: host modes from the console.
AdminResponse ConsoleMode(std::string_view method, std::string_view rest,
                          std::string_view body, const AdminContext& context) {
  if (context.modes == nullptr || !context.publish_modes) {
    return Error(404, "console host modes unavailable");
  }
  std::string error;
  if (rest.empty() && method == "POST") {
    const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
    if (json.is_discarded() || !json.is_object()) {
      return Error(400, "body must be a JSON object");
    }
    const auto host = json.find("host");
    const auto mode_text = json.find("mode");
    HostMode mode = HostMode::kShadow;
    if (host == json.end() || !host->is_string() || mode_text == json.end() ||
        !mode_text->is_string() ||
        !ParseHostMode(mode_text->get<std::string>(), &mode)) {
      return Error(
          400, R"(expected {"host": "<host>", "mode": "shadow|enforce|off"})");
    }
    if (!context.modes->Set(host->get<std::string>(), mode, &error)) {
      return Error(400, error);
    }
    context.publish_modes();
    const std::string name = NormalizeHost(host->get<std::string>());
    log::Warn("admin: host mode of {} set to {} (console)", name,
              HostModeName(mode));
    return {200, {{"host", name}, {"mode", HostModeName(mode)}}};
  }
  if (!rest.empty() && method == "DELETE") {
    const std::string host = PercentDecode(rest.substr(1));
    if (!context.modes->Remove(host, &error)) return Error(404, error);
    context.publish_modes();
    log::Info("admin: console host mode of {} removed", host);
    return {200, {{"removed", NormalizeHost(host)}}};
  }
  return Error(405, "method not allowed");
}

AdminResponse Lists(std::string_view method, std::string_view rest,
                    std::string_view body, const AdminContext& context,
                    int64_t now_seconds) {
  if (rest.empty() && method == "GET") {
    nlohmann::json entries = nlohmann::json::array();
    for (const ListEntry& entry : context.lists->Entries(now_seconds)) {
      entries.push_back(ListStore::ToJson(entry));
    }
    return {200, {{"entries", entries}}};
  }
  if (rest.empty() && method == "POST") {
    const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
    ListEntry entry;
    std::string error;
    if (json.is_discarded() ||
        !ListStore::FromJson(json, now_seconds, &entry, &error)) {
      return Error(400, json.is_discarded() ? "body must be JSON" : error);
    }
    ListEntry stored;
    if (!context.lists->Add(std::move(entry), now_seconds, &stored, &error)) {
      return Error(500, error);
    }
    log::Info("admin: list entry {} added: {} {} {}", stored.id,
              ActionName(stored.action), ListKindName(stored.kind),
              stored.value);
    return {201, ListStore::ToJson(stored)};
  }
  if (!rest.empty() && method == "DELETE") {
    uint64_t id = 0;
    const std::string_view text = rest.substr(1);
    const auto [ptr, ec] =
        std::from_chars(text.data(), text.data() + text.size(), id);
    if (ec != std::errc() || ptr != text.data() + text.size()) {
      return Error(400, "expected /lists/<id>");
    }
    std::string error;
    if (!context.lists->Remove(id, &error)) return Error(404, error);
    log::Info("admin: list entry {} removed", id);
    return {200, {{"removed", id}}};
  }
  return Error(405, "method not allowed");
}

nlohmann::json AttackToJson(const AttackEntry& entry) {
  nlohmann::json json = {
      {"host", entry.host}, {"source", entry.source}, {"since", entry.since}};
  if (entry.until != 0) json["until"] = entry.until;
  if (!entry.kind.empty()) {
    json["signature"] = {{"kind", entry.kind}, {"value", entry.value}};
  }
  if (entry.threshold != 0) json["threshold"] = entry.threshold;
  return json;
}

// Under-attack mode: GET lists hosts and the history of activations
// (manual and automatic, newest first), POST {"host": "<host>|*", "ttl":
// "1h"} switches one on (no ttl: until switched off), DELETE /attack/<host>
// switches it off.
AdminResponse Attack(std::string_view method, std::string_view rest,
                     std::string_view body, const AdminContext& context,
                     int64_t now_seconds) {
  if (context.attack == nullptr) return Error(404, "attack mode unavailable");
  if (rest.empty() && method == "GET") {
    nlohmann::json entries = nlohmann::json::array();
    for (const AttackEntry& entry : context.attack->Entries(now_seconds)) {
      entries.push_back(AttackToJson(entry));
    }
    nlohmann::json history = nlohmann::json::array();
    for (const AttackRecord& record : context.attack->History(now_seconds)) {
      nlohmann::json item = AttackToJson(record.entry);
      if (record.ended != 0) item["ended"] = record.ended;
      history.push_back(std::move(item));
    }
    return {200,
            {{"entries", entries},
             {"history", history},
             {"auto_rps", context.attack->auto_rps()},
             {"auto_rps_total", context.attack->auto_rps_total()}}};
  }
  if (rest.empty() && method == "POST") {
    const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
    if (json.is_discarded() || !json.is_object()) {
      return Error(400, "body must be a JSON object");
    }
    const auto host = json.find("host");
    if (host == json.end() || !host->is_string()) {
      return Error(400, R"(expected {"host": "<host>" or "*"})");
    }
    AttackEntry entry;
    entry.host = host->get<std::string>();
    entry.source = "admin";
    entry.since = now_seconds;
    if (const auto ttl = json.find("ttl"); ttl != json.end()) {
      int64_t seconds = 0;
      std::chrono::milliseconds duration{0};
      if (ttl->is_number_integer()) {
        seconds = ttl->get<int64_t>();
      } else if (ttl->is_string() &&
                 ParseDuration(ttl->get<std::string>(), &duration)) {
        seconds =
            std::chrono::duration_cast<std::chrono::seconds>(duration).count();
      }
      if (seconds <= 0) {
        return Error(400, "ttl must be positive seconds or a duration like 1h");
      }
      entry.until = now_seconds + seconds;
    }
    std::string error;
    if (!context.attack->Enable(entry, now_seconds, &error)) {
      return Error(400, error);
    }
    log::Warn("admin: under-attack mode on for {}", entry.host);
    entry.host = NormalizeHost(entry.host);
    return {201, AttackToJson(entry)};
  }
  if (!rest.empty() && method == "DELETE") {
    const std::string host = PercentDecode(rest.substr(1));
    if (!context.attack->Disable(host, now_seconds)) {
      return Error(404, "host is not under attack");
    }
    log::Info("admin: under-attack mode off for {}", host);
    return {200, {{"removed", host}}};
  }
  return Error(405, "method not allowed");
}

// A decision with the client's ip_prefix and ip_hash as in events, so a
// consumer that must not see full addresses can drop "ip" and still join
// the decision with events.
nlohmann::json DecisionWithPrefix(const DecisionRecord& record,
                                  const AdminContext& context) {
  nlohmann::json json = DecisionToJson(record);
  std::error_code ec;
  const asio::ip::address address = asio::ip::make_address(record.ip, ec);
  if (ec) return json;
  json["ip_prefix"] = IpPrefix(address);
  if (context.event_settings != nullptr) {
    json["ip_hash"] = IpHash(address, context.event_settings->ip_salt);
  }
  return json;
}

AdminResponse Decisions(std::string_view rest, const QueryParams& params,
                        const AdminContext& context) {
  if (!rest.empty()) {
    const auto record = context.decisions->Find(rest.substr(1));
    if (!record) return Error(404, "unknown request id (log is bounded)");
    return {200, DecisionWithPrefix(*record, context)};
  }
  std::size_t limit = 50;
  if (const std::string text = QueryParam(params, "limit"); !text.empty()) {
    const auto [ptr, ec] =
        std::from_chars(text.data(), text.data() + text.size(), limit);
    if (ec != std::errc() || limit == 0 || limit > 1000) {
      return Error(400, "limit must be 1..1000");
    }
  }
  nlohmann::json records = nlohmann::json::array();
  for (const DecisionRecord& record : context.decisions->Recent(
           limit, NormalizeHost(QueryParam(params, "host")),
           QueryParam(params, "class"))) {
    records.push_back(DecisionWithPrefix(record, context));
  }
  return {200, {{"decisions", records}}};
}

int64_t Millis(std::chrono::milliseconds duration) { return duration.count(); }

nlohmann::json LimitJson(const RateLimitSpec& spec) {
  return {{"name", spec.name},       {"hosts", spec.hosts},
          {"paths", spec.paths},     {"methods", spec.methods},
          {"classes", spec.classes}, {"key", spec.key},
          {"count", spec.count},     {"period_ms", Millis(spec.period)},
          {"burst", spec.burst},     {"statuses", spec.statuses}};
}

// GET /config: what decides verdicts right now (the last successful load
// or reload), without secrets or file paths.
AdminResponse ConfigView(const AdminContext& context) {
  const auto verdicts = context.verdicts->snapshot();
  const Config& config = *verdicts->config;
  const PolicySettings& policy = verdicts->policy->settings();
  nlohmann::json rules = nlohmann::json::array();
  for (const RuleSpec& rule : config.rules) {
    nlohmann::json json = {
        {"name", rule.name}, {"when", rule.when}, {"action", rule.action}};
    if (rule.action == "score") json["score"] = rule.score;
    rules.push_back(std::move(json));
  }
  nlohmann::json limits = nlohmann::json::array();
  for (const RateLimitSpec& spec : config.rate_limits) {
    limits.push_back(LimitJson(spec));
  }
  nlohmann::json crawlers = nlohmann::json::array();
  for (const KnownCrawler& crawler : KnownCrawlers()) {
    nlohmann::json json = {{"id", crawler.id}, {"ai", crawler.ai}};
    json["domains"] = nlohmann::json::array();
    for (const std::string_view domain : crawler.domains) {
      json["domains"].push_back(domain);
    }
    json["ranges"] = nlohmann::json::array();
    for (const std::string_view url : crawler.ranges) {
      json["ranges"].push_back(url);
    }
    crawlers.push_back(std::move(json));
  }
  nlohmann::json automation = nlohmann::json::array();
  nlohmann::json browsers = nlohmann::json::array();
  for (const BrowserProfile& profile : verdicts->library->browsers()) {
    browsers.push_back({{"id", profile.id},
                        {"engines", profile.engines},
                        {"ja4_ciphers", profile.ja4_ciphers},
                        {"h2_pseudo_orders", profile.h2_pseudo_orders}});
  }
  for (const AutomationSignature& signature : verdicts->library->automation()) {
    automation.push_back({{"id", signature.id},
                          {"weight", signature.weight},
                          {"ja4", signature.ja4},
                          {"h2_fp", signature.h2_fingerprint},
                          {"header_fp", signature.header_fp},
                          {"user_agent", signature.user_agent}});
  }
  nlohmann::json weights = nlohmann::json::object();
  for (const auto& [signal, weight] : verdicts->library->weights()) {
    weights[signal] = weight;
  }
  return {200,
          {{"generation", verdicts->generation},
           {"built_at_ms", verdicts->built_at_ms},
           {"policy",
            {{"enforce", policy.enforce},
             {"suspicious_threshold", policy.suspicious_threshold},
             {"bot_threshold", policy.bot_threshold},
             {"suspicious_action", ActionName(policy.suspicious_action)},
             {"bot_action", ActionName(policy.bot_action)},
             {"verified_bot_action", ActionName(policy.verified_bot_action)},
             {"block_status", policy.block_status}}},
           {"rules", rules},
           {"rate_limits", limits},
           {"throttle", config.throttle ? LimitJson(*config.throttle)
                                        : nlohmann::json(nullptr)},
           {"honeypot_paths", verdicts->honeypot_paths},
           {"crawlers",
            {{"verify", config.crawlers_verify},
             {"ip_ranges", config.crawlers_ip_ranges},
             {"ai_action",
              verdicts->ai_crawler_action
                  ? nlohmann::json(ActionName(*verdicts->ai_crawler_action))
                  : nlohmann::json(nullptr)},
             {"catalog", crawlers}}},
           {"web_bot_auth",
            {{"enabled", config.web_bot_auth_enabled},
             {"trusted", verdicts->trusted_agents}}},
           {"challenge",
            {{"suspicious_difficulty", config.challenge_suspicious_difficulty},
             {"bot_difficulty", config.challenge_bot_difficulty},
             {"token_ttl_ms", Millis(config.challenge_token_ttl)},
             {"token_credit", config.challenge_token_credit}}},
           {"captcha",
            {{"provider", config.captcha_provider},
             {"escalate", config.captcha_escalate},
             {"rounds", config.captcha_rounds}}},
           {"attack",
            {{"auto_rps", config.attack_auto_rps},
             {"auto_rps_total", config.attack_auto_rps_total},
             {"persistent", !config.admin_attack_file.empty()},
             {"auto_duration_ms", Millis(config.attack_auto_duration)}}},
           {"library",
            {{"version", verdicts->library->version()},
             {"profiles", verdicts->library->profile_count()},
             {"browsers", browsers},
             {"weights", weights},
             {"automation", automation}}},
           {"model",
            {{"loaded", verdicts->model != nullptr},
             {"threshold", verdicts->model_threshold}}}}};
}

std::string JsonString(const nlohmann::json& json, std::string_view key) {
  const auto it = json.find(key);
  return it != json.end() && it->is_string() ? it->get<std::string>() : "";
}

// One sample of POST /rules/test: a request event (bot_shield.req row).
struct RuleSample {
  HttpRequest request;
  std::string host, path, sni, alpn, ja4, h2_fp, pseudo_order, header_fp,
      tcp_fp, bot_class, signed_agent;
  std::vector<std::string> reasons;
  UserAgent ua;
  int64_t score = 0;
  int64_t asn = 0;
  int64_t tcp_rtt_ms = -1;
  int64_t handshake_ms = -1;
  asio::ip::address ip;
};

bool ParseSample(const nlohmann::json& json, RuleSample* sample) {
  if (!json.is_object()) return false;
  sample->request.method = JsonString(json, "method");
  sample->request.version = JsonString(json, "http_version");
  const std::string user_agent = JsonString(json, "user_agent");
  if (!user_agent.empty()) {
    sample->request.headers.emplace_back("user-agent", user_agent);
  }
  sample->ua = ParseUserAgent(user_agent);
  sample->host = NormalizeHost(JsonString(json, "host"));
  sample->path = JsonString(json, "path");
  sample->sni = JsonString(json, "sni");
  sample->alpn = JsonString(json, "alpn");
  sample->ja4 = JsonString(json, "ja4");
  sample->h2_fp = JsonString(json, "h2_fp");
  sample->pseudo_order = JsonString(json, "pseudo_order");
  sample->header_fp = JsonString(json, "header_fp");
  sample->tcp_fp = JsonString(json, "tcp_fp");
  sample->bot_class = JsonString(json, "class");
  sample->signed_agent = JsonString(json, "signed_agent");
  if (const auto it = json.find("score"); it != json.end()) {
    if (!it->is_number_integer()) return false;
    sample->score = it->get<int64_t>();
  }
  if (const auto it = json.find("asn"); it != json.end()) {
    if (!it->is_number_integer()) return false;
    sample->asn = it->get<int64_t>();
  }
  // Round trips in microseconds as in events; null or absent: unknown.
  for (const auto& [key, field] :
       {std::pair{"tcp_rtt_us", &RuleSample::tcp_rtt_ms},
        std::pair{"handshake_us", &RuleSample::handshake_ms}}) {
    const auto it = json.find(key);
    if (it == json.end() || it->is_null()) continue;
    if (!it->is_number_integer()) return false;
    sample->*field = it->get<int64_t>() / 1000;
  }
  if (const auto it = json.find("reasons"); it != json.end()) {
    if (!it->is_array()) return false;
    for (const nlohmann::json& reason : *it) {
      if (!reason.is_string()) return false;
      sample->reasons.push_back(reason.get<std::string>());
    }
  }
  // Events carry a prefix, not the address: cidr() sees its network.
  const std::string prefix = JsonString(json, "ip_prefix");
  std::error_code ec;
  sample->ip = asio::ip::make_address(prefix.substr(0, prefix.find('/')), ec);
  return true;
}

// POST /rules/test {"when": "<condition>", "samples": [<req event>, ...]}:
// compiles the condition like a rule in the configuration and evaluates it
// on the samples. 422 with the column on a compile error.
AdminResponse RulesTest(std::string_view body, const AdminContext& context) {
  const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
  if (json.is_discarded() || !json.is_object()) {
    return Error(400, "body must be a JSON object");
  }
  const auto when = json.find("when");
  if (when == json.end() || !when->is_string()) {
    return Error(400, R"(expected {"when": "<condition>", "samples": [...]})");
  }
  const auto samples = json.find("samples");
  if (samples != json.end() &&
      (!samples->is_array() || samples->size() > kMaxSamples)) {
    return Error(
        400, std::format("samples: an array of up to {} events", kMaxSamples));
  }
  std::string error;
  const auto condition = Condition::Compile(when->get<std::string>(), &error);
  if (!condition) {
    AdminResponse response = Error(422, error);
    int column = 0;
    if (error.starts_with("col ")) {
      std::from_chars(error.data() + 4, error.data() + error.size(), column);
    }
    response.body["column"] = column;
    return response;
  }
  const auto asn = context.asn != nullptr ? context.asn->snapshot() : nullptr;
  nlohmann::json matched = nlohmann::json::array();
  std::size_t evaluated = 0;
  if (samples != json.end()) {
    for (std::size_t i = 0; i < samples->size(); ++i) {
      RuleSample sample;
      if (!ParseSample((*samples)[i], &sample)) {
        return Error(400, std::format("samples[{}]: bad event", i));
      }
      RuleContext rule;
      rule.request = &sample.request;
      rule.ip = sample.ip;
      rule.host = sample.host;
      rule.path = sample.path;
      rule.sni = sample.sni;
      rule.alpn = sample.alpn;
      rule.ja4 = sample.ja4;
      rule.h2_fingerprint = sample.h2_fp;
      rule.pseudo_order = sample.pseudo_order;
      rule.header_fp = sample.header_fp;
      rule.tcp_fingerprint = sample.tcp_fp;
      rule.ua_family = sample.ua.family;
      rule.ua_engine = sample.ua.engine;
      rule.ua_os = sample.ua.os;
      rule.ua_tool = sample.ua.tool;
      rule.score = sample.score;
      rule.bot_class = sample.bot_class;
      rule.reasons = &sample.reasons;
      rule.asn = sample.asn;
      rule.signed_agent = sample.signed_agent;
      rule.tcp_rtt_ms = sample.tcp_rtt_ms;
      rule.handshake_ms = sample.handshake_ms;
      if (asn && sample.asn > 0) {
        if (const auto info = asn->Find(static_cast<uint32_t>(sample.asn))) {
          rule.asn_org = info->org;
          rule.asn_country = info->country;
          rule.asn_hosting = info->hosting;
        }
      }
      if (condition->Evaluate(rule)) matched.push_back(i);
      ++evaluated;
    }
  }
  return {200,
          {{"references", condition->References()},
           {"evaluated", evaluated},
           {"matched", matched}}};
}

// GET /asn?numbers=13335,64500: names from the gateway's ASN database.
AdminResponse AsnNames(const QueryParams& params, const AdminContext& context) {
  const auto database =
      context.asn != nullptr ? context.asn->snapshot() : nullptr;
  nlohmann::json asns = nlohmann::json::array();
  const std::string list = QueryParam(params, "numbers");
  std::string_view numbers = list;
  std::size_t count = 0;
  while (!numbers.empty()) {
    const std::size_t comma = numbers.find(',');
    const std::string_view item = numbers.substr(0, comma);
    numbers.remove_prefix(comma == std::string_view::npos ? numbers.size()
                                                          : comma + 1);
    uint32_t number = 0;
    const auto [ptr, ec] =
        std::from_chars(item.data(), item.data() + item.size(), number);
    if (ec != std::errc() || ptr != item.data() + item.size()) {
      return Error(400, "numbers: comma-separated AS numbers");
    }
    if (++count > kMaxAsns) {
      return Error(400, std::format("numbers: at most {}", kMaxAsns));
    }
    if (!database) continue;
    if (const auto info = database->Find(number)) {
      asns.push_back({{"asn", info->asn},
                      {"org", info->org},
                      {"country", info->country},
                      {"hosting", info->hosting}});
    }
  }
  return {200, {{"loaded", database != nullptr}, {"asns", asns}}};
}

asio::awaitable<void> HandleConnection(stream_protocol::socket socket,
                                       const AdminContext& context) {
  auto executor = co_await asio::this_coro::executor;
  ScopedWatchdog deadline(executor, kRequestTimeout, [&socket] {
    std::error_code ec;
    socket.close(ec);
  });
  std::string data;
  auto [ec, head_size] = co_await asio::async_read_until(
      socket, asio::dynamic_buffer(data, kMaxHead), "\r\n\r\n", kUse);
  if (ec) co_return;

  const std::string_view head = std::string_view(data).substr(0, head_size);
  // A copy: reading the body below may reallocate `data` (and `head`).
  const std::string line(head.substr(0, head.find("\r\n")));
  const std::size_t first_space = line.find(' ');
  const std::size_t second_space = line.find(' ', first_space + 1);
  std::size_t content_length = 0;
  {
    std::string lower(head);
    for (char& c : lower) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (const auto at = lower.find("\r\ncontent-length:");
        at != std::string::npos) {
      std::string_view value = std::string_view(lower).substr(at + 17);
      while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
      std::from_chars(value.data(), value.data() + value.size(),
                      content_length);
    }
  }
  if (content_length > kMaxBody) co_return;
  if (data.size() < head_size + content_length) {
    const std::size_t missing = head_size + content_length - data.size();
    std::string rest(missing, '\0');
    auto [read_ec, n] =
        co_await asio::async_read(socket, asio::buffer(rest), kUse);
    if (read_ec) co_return;
    data += rest;
  }

  AdminResponse response;
  if (first_space == std::string_view::npos ||
      second_space == std::string_view::npos) {
    response = Error(400, "bad request line");
  } else {
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    response = HandleAdminRequest(
        line.substr(0, first_space),
        line.substr(first_space + 1, second_space - first_space - 1),
        std::string_view(data).substr(head_size, content_length), context, now);
  }
  const std::string body =
      response.body.dump(2, ' ', false,
                         nlohmann::json::error_handler_t::replace) +
      "\n";
  const std::string reply = std::format(
      "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\n"
      "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
      response.status, ReasonPhrase(response.status), body.size(), body);
  co_await asio::async_write(socket, asio::buffer(reply), kUse);
}

}  // namespace

AdminResponse HandleAdminRequest(std::string_view method,
                                 std::string_view target, std::string_view body,
                                 const AdminContext& context,
                                 int64_t now_seconds) {
  const std::size_t question = target.find('?');
  const std::string_view path = target.substr(0, question);
  const auto params = ParseQuery(question == std::string_view::npos
                                     ? std::string_view()
                                     : target.substr(question + 1));
  if (path == "/status") {
    if (method != "GET") return Error(405, "method not allowed");
    return Status(context, now_seconds);
  }
  if (path == "/config") {
    if (method != "GET") return Error(405, "method not allowed");
    return ConfigView(context);
  }
  if (path == "/policy" && method == "GET") {
    const std::string host = QueryParam(params, "host");
    return host.empty() ? PolicyOverview(context) : HostPolicy(context, host);
  }
  if (path == "/policy" || path.starts_with("/policy/")) {
    return ConsoleMode(method, path.substr(7), body, context);
  }
  if (path == "/rules/test") {
    if (method != "POST") return Error(405, "method not allowed");
    return RulesTest(body, context);
  }
  if (path == "/asn") {
    if (method != "GET") return Error(405, "method not allowed");
    return AsnNames(params, context);
  }
  if (path == "/reload") {
    if (method != "POST") return Error(405, "method not allowed");
    if (!context.reload) return Error(501, "reload is not available");
    std::string summary;
    if (!context.reload(&summary)) return Error(422, summary);
    return {200, {{"reloaded", true}, {"summary", summary}}};
  }
  if (path == "/settings" || path.starts_with("/settings/")) {
    return HandleSettingsRequest(method, path.substr(9), body, context,
                                 now_seconds * 1000);
  }
  if (path == "/lists" || path.starts_with("/lists/")) {
    return Lists(method, path.substr(6), body, context, now_seconds);
  }
  if (path == "/attack" || path.starts_with("/attack/")) {
    return Attack(method, path.substr(7), body, context, now_seconds);
  }
  if (path == "/decisions" || path.starts_with("/decisions/")) {
    if (method != "GET") return Error(405, "method not allowed");
    return Decisions(path.substr(10), params, context);
  }
  return Error(404, "unknown endpoint");
}

bool OpenAdminSocket(stream_protocol::acceptor* acceptor,
                     const std::string& path, std::string* error) {
  std::remove(path.c_str());  // A stale socket from a previous run.
  std::error_code ec;
  const stream_protocol::endpoint endpoint(path);
  acceptor->open(endpoint.protocol(), ec);
  if (!ec) acceptor->bind(endpoint, ec);
  if (!ec) acceptor->listen(16, ec);
  if (ec) {
    *error = std::format("admin socket {}: {}", path, ec.message());
    return false;
  }
  if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
    *error = std::format("admin socket {}: chmod failed", path);
    return false;
  }
  return true;
}

asio::awaitable<void> ServeAdmin(stream_protocol::acceptor& acceptor,
                                 const AdminContext& context) {
  auto executor = co_await asio::this_coro::executor;
  while (true) {
    auto [ec, socket] = co_await acceptor.async_accept(kUse);
    if (ec) {
      if (!acceptor.is_open()) co_return;
      continue;
    }
    asio::co_spawn(executor, HandleConnection(std::move(socket), context),
                   asio::detached);
  }
}

AdminServer::~AdminServer() {
  Stop();
  Join();
}

bool AdminServer::Start(const std::string& path, const AdminContext* context,
                        std::string* error) {
  acceptor_ = std::make_unique<stream_protocol::acceptor>(io_context_);
  if (!OpenAdminSocket(acceptor_.get(), path, error)) return false;
  asio::co_spawn(io_context_, ServeAdmin(*acceptor_, *context),
                 [](const std::exception_ptr& failure) {
                   if (!failure) return;
                   try {
                     std::rethrow_exception(failure);
                   } catch (const std::exception& e) {
                     log::Error("admin API stopped: {}", e.what());
                   }
                 });
  thread_ = std::thread([this] {
    try {
      io_context_.run();
    } catch (const std::exception& e) {
      log::Error("admin API stopped: {}", e.what());
    }
  });
  log::Info("admin API on {}", path);
  return true;
}

void AdminServer::StopAccepting() {
  if (!acceptor_) return;
  asio::post(io_context_, [this] {
    std::error_code ec;
    acceptor_->close(ec);
  });
}

void AdminServer::Stop() { io_context_.stop(); }

void AdminServer::Join() {
  if (thread_.joinable()) thread_.join();
}

}  // namespace bot_shield
