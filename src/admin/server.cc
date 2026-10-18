#include "admin/server.h"

#include <sys/stat.h>

#include <algorithm>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/local/stream_protocol.hpp>
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
#include <format>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "common/host.h"
#include "common/log.h"
#include "common/metrics.h"
#include "common/url.h"
#include "common/version.h"
#include "config/config.h"
#include "docker/labels.h"
#include "net/watchdog.h"
#include "proxy/http_message.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

using asio::local::stream_protocol;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kMaxRequest = std::size_t{64} * 1024;
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
       {"mode", context.policy->global_enforce() ? "enforce" : "shadow"},
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
       {"events_dropped", metrics.events_dropped.Get()}}};
}

AdminResponse HostPolicy(const AdminContext& context,
                         const std::string& raw_host) {
  const std::string host = NormalizeHost(raw_host);
  if (host.empty()) return Error(400, "host parameter is required");
  const auto labels =
      context.labels != nullptr ? context.labels->snapshot() : nullptr;
  const ModeResolution mode = context.policy->ResolveMode(
      host, labels ? labels->ModeFor(host) : std::nullopt);
  const bool passthrough_config = std::ranges::any_of(
      context.config->passthrough_hosts,
      [&](const std::string& pattern) { return HostMatches(pattern, host); });
  const bool passthrough_labels = labels && labels->IsPassthrough(host);
  std::vector<std::string> limits = context.rate_limits->NamesForHost(host);
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
  return json;
}

// Under-attack mode: GET lists hosts, POST {"host": "<host>|*", "ttl":
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
    return {200,
            {{"entries", entries}, {"auto_rps", context.attack->auto_rps()}}};
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
    if (!context.attack->Disable(host)) {
      return Error(404, "host is not under attack");
    }
    log::Info("admin: under-attack mode off for {}", host);
    return {200, {{"removed", host}}};
  }
  return Error(405, "method not allowed");
}

AdminResponse Decisions(std::string_view rest, const QueryParams& params,
                        const AdminContext& context) {
  if (!rest.empty()) {
    const auto record = context.decisions->Find(rest.substr(1));
    if (!record) return Error(404, "unknown request id (log is bounded)");
    return {200, DecisionToJson(*record)};
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
    records.push_back(DecisionToJson(record));
  }
  return {200, {{"decisions", records}}};
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
      socket, asio::dynamic_buffer(data, kMaxRequest), "\r\n\r\n", kUse);
  if (ec) co_return;

  const std::string_view head = std::string_view(data).substr(0, head_size);
  const std::string_view line = head.substr(0, head.find("\r\n"));
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
  if (content_length > kMaxRequest) co_return;
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
  if (path == "/policy") {
    if (method != "GET") return Error(405, "method not allowed");
    return HostPolicy(context, QueryParam(params, "host"));
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

}  // namespace bot_shield
