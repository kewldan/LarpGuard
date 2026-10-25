#include "server/connection.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <asio/as_tuple.hpp>
#include <asio/connect.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/post.hpp>
#include <asio/ssl/host_name_verification.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "action/actions.h"
#include "admin/attack.h"
#include "admin/lists.h"
#include "behavior/behavior.h"
#include "challenge/captcha.h"
#include "challenge/challenger.h"
#include "challenge/token.h"
#include "common/hash.h"
#include "common/host.h"
#include "common/log.h"
#include "common/metrics.h"
#include "common/network.h"
#include "common/url.h"
#include "config/config.h"
#include "crawler/crawlers.h"
#include "crawler/ranges.h"
#include "crawler/verifier.h"
#include "crawler/web_bot_auth.h"
#include "docker/labels.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "fp/h1_tap.h"
#include "fp/http_fingerprint.h"
#include "fp/http_request.h"
#include "fp/ja4.h"
#include "fp/library.h"
#include "fp/tcp_syn.h"
#include "fp/user_agent.h"
#include "model/features.h"
#include "net/asn.h"
#include "net/classifier.h"
#include "net/prefixed_stream.h"
#include "net/proxy_protocol.h"
#include "net/socket_options.h"
#include "net/watchdog.h"
#include "proxy/exchange.h"
#include "proxy/h1_server.h"
#include "proxy/h2_server.h"
#include "proxy/http_message.h"
#include "proxy/proxy_hooks.h"
#include "proxy/transport.h"
#include "ratelimit/gcra.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "score/rules.h"
#include "score/scorer.h"
#include "server/verdicts.h"
#include "server/whoami.h"
#include "tls/cert_store.h"
#include "tls/client_hello.h"
#include "xdp/xdp_filter.h"

#if BOT_SHIELD_FOXIO
#include "fp/foxio/ja4plus.h"
#endif

namespace bot_shield {
namespace {

using asio::ip::tcp;
// Used by `co_await (a && b)`; clang-tidy does not see operator lookups.
// NOLINTNEXTLINE(misc-unused-using-decls)
using asio::experimental::awaitable_operators::operator&&;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kHelloReadChunk = 4096;
constexpr std::size_t kPumpBufferSize = std::size_t{16} * 1024;

using ClientTlsStream = asio::ssl::stream<PrefixedStream<tcp::socket>>;

struct ConnectionInfo {
  uint64_t id = 0;
  tcp::endpoint peer;
  tcp::endpoint local;
};

// Connection ids for logs and events, shared by TCP and QUIC.
uint64_t NextConnectionId() {
  static std::atomic<uint64_t> next_id{1};
  return next_id.fetch_add(1, std::memory_order_relaxed);
}

ConnectionInfo MakeConnectionInfo(const tcp::socket& socket) {
  ConnectionInfo info;
  info.id = NextConnectionId();
  std::error_code ec;
  info.peer = socket.remote_endpoint(ec);
  info.local = socket.local_endpoint(ec);
  return info;
}

// Keeps the active-connections gauge in sync with handler lifetimes.
class ActiveConnection {
 public:
  ActiveConnection() { GlobalMetrics().connections_active.Add(1); }
  ~ActiveConnection() { GlobalMetrics().connections_active.Add(-1); }

  ActiveConnection(const ActiveConnection&) = delete;
  ActiveConnection& operator=(const ActiveConnection&) = delete;
};

// Host part of an authority, normalized ("Shop.Test:443" -> "shop.test").
int64_t SteadyNanos() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

std::string HostOnly(std::string_view authority) {
  if (authority.starts_with('[')) {
    return NormalizeHost(authority.substr(0, authority.find(']') + 1));
  }
  return NormalizeHost(authority.substr(0, authority.find(':')));
}

// A per-IP slot for a connection that has not finished its first request's
// headers yet; released then, when the connection is passed through, or when
// it ends.
class PendingSlot {
 public:
  PendingSlot() = default;
  ~PendingSlot() { Release(); }

  PendingSlot(const PendingSlot&) = delete;
  PendingSlot& operator=(const PendingSlot&) = delete;

  // False if `ip` already has `limit` pending connections.
  bool Acquire(ConnectionCounter* counter, std::string ip, std::size_t limit) {
    if (!counter->Acquire(ip, limit)) return false;
    counter_ = counter;
    ip_ = std::move(ip);
    return true;
  }
  void Release() {
    if (counter_ == nullptr) return;
    counter_->Release(ip_);
    counter_ = nullptr;
  }

 private:
  ConnectionCounter* counter_ = nullptr;
  std::string ip_;
};

// Per-connection observation: fingerprints, byte counters and the passive HTTP
// taps. Emits a "conn" event when the handler finishes and a "req" event for
// every request the taps see. Never touches the proxied bytes.
class ConnectionObserver {
 public:
  ConnectionObserver(const GatewayContext& context, const ConnectionInfo& info,
                     std::string listener)
      : context_(context) {
    record_.id = info.id;
    record_.started_ms = UnixMillis();
    record_.listener = std::move(listener);
    record_.peer = info.peer.address();
    LookupAsn();
    LookupThreatLists();
  }

  ~ConnectionObserver() {
    if (context_.events == nullptr) return;
    try {
      context_.events->Publish(
          "conn",
          ConnectionEventJson(record_, *context_.event_settings, UnixMillis()));
    } catch (...) {
      // Destructors must not throw; logging could throw again.
      GlobalMetrics().events_dropped.Inc();
    }
  }

  ConnectionObserver(const ConnectionObserver&) = delete;
  // Executor of the connection (timers of tarpit answers).
  void set_executor(asio::any_io_executor executor) {
    executor_ = std::move(executor);
  }
  ConnectionObserver& operator=(const ConnectionObserver&) = delete;

  ConnectionRecord& record() { return record_; }
  // Released once the first request's headers are in.
  void set_pending_slot(PendingSlot* slot) { pending_slot_ = slot; }

  // The peer's autonomous system, once per connection (the address does
  // not change; QUIC migration is off).
  // Once per connection, like the ASN: the address does not change.
  void LookupThreatLists() {
    if (context_.threat_lists == nullptr) return;
    threat_lists_ = ThreatListStore::Match(*context_.threat_lists->snapshot(),
                                           record_.peer);
  }

  void LookupAsn() {
    if (context_.asn == nullptr) return;
    const std::shared_ptr<const AsnDatabase> db = context_.asn->snapshot();
    if (db == nullptr) return;
    const std::optional<AsnInfo> info = db->Lookup(record_.peer);
    if (!info) return;
    record_.asn = info->asn;
    asn_org_ = std::string(info->org);
    asn_country_ = std::string(info->country);
    asn_hosting_ = info->hosting;
  }

  void OnSyn(std::span<const uint8_t> packet) {
    TcpSyn syn;
    if (!ParseTcpSyn(packet, &syn)) return;
    record_.tcp_fingerprint = TcpFingerprint(syn);
    record_.tcp_initial_ttl = InitialTtl(syn.ttl);
#if BOT_SHIELD_FOXIO
    record_.ja4t = foxio::Ja4t(syn);
#endif
  }

  void OnClientHello(const ClientHello& hello) {
    record_.server_name = hello.server_name;
    record_.tls_version = TlsVersionCode(hello);
    if (!hello.alpn.empty()) record_.alpn_offered = hello.alpn.front();
    record_.offered_h2 = hello.HasAlpn("h2");
    record_.ja4 = Ja4(hello);
    record_.ja4_raw = Ja4Raw(hello);
  }

  void OnQuicClientHello(const ClientHello& hello, std::string transport) {
    record_.server_name = hello.server_name;
    record_.tls_version = TlsVersionCode(hello);
    if (!hello.alpn.empty()) record_.alpn_offered = hello.alpn.front();
    record_.offered_h2 = hello.HasAlpn("h3");
    record_.alpn = "h3";
    record_.quic = true;
    record_.quic_fp = std::move(transport);
    record_.ja4 = Ja4(hello, 'q');
    record_.ja4_raw = Ja4Raw(hello, 'q');
  }

  void OnRoute(std::string_view route, std::string_view reason) {
    record_.route = route;
    record_.reason = reason;
  }

  // Starts reading the plaintext HTTP/1.x a client sends on port 80. Only
  // with events on: nothing else consumes what the tap produces. Terminated
  // TLS traffic goes through the proxy instead.
  void StartHttpTap() {
    if (context_.events == nullptr || !context_.event_settings->requests) {
      return;
    }
    h1_ = std::make_unique<H1Tap>(
        [this](HttpRequest&& request) { OnRequest(std::move(request)); });
  }

  void OnClientData(std::span<const uint8_t> data) {
    record_.bytes_in += data.size();
    GlobalMetrics().bytes_client_to_upstream.Inc(data.size());
    if (h1_ && h1_->active()) h1_->Feed(data);
  }

  void OnUpstreamData(std::span<const uint8_t> data) {
    OnBytesToClient(data.size());
  }

  void OnBytesToClient(std::size_t size) {
    record_.bytes_out += size;
    GlobalMetrics().bytes_upstream_to_client.Inc(size);
  }

  // Request headers are parsed: score them, tell Traefik the verdict in
  // X-Bot-* headers and, when enforcing, answer a block ourselves.
  void OnProxyRequest(Exchange& exchange) {
    if (pending_slot_ != nullptr) {
      pending_slot_->Release();
      pending_slot_ = nullptr;
    }
    exchange.request_id = std::format("{}-{}-{}",
                                      context_.event_settings != nullptr
                                          ? context_.event_settings->instance
                                          : "local",
                                      record_.id, ++request_sequence_);
    exchange.request.headers.emplace_back("x-bot-request-id",
                                          exchange.request_id);
    const int64_t now = UnixMillis() / 1000;
    // One snapshot for the whole request, even if a reload lands meanwhile.
    if (context_.verdicts != nullptr) verdicts_ = context_.verdicts->snapshot();
    const ClientBinding binding = ClientBinding::For(
        BindingStack(
            record_.ja4,
            ParseUserAgent(exchange.observed.Header("user-agent")).engine,
            verdicts_ != nullptr ? *verdicts_->library
                                 : FingerprintLibrary::BuiltIn()),
        IpPrefix(record_.peer));
    const std::string_view target = exchange.request.path;
    const bool whoami =
        target.substr(0, target.find('?')) == kWhoamiPath && WhoamiEnabled();
    if (whoami && !ChallengeEndpointAllowed(exchange)) return;
    if (context_.challenger != nullptr) {
      // The clearance cookie is ours; the application never sees it.
      for (auto& [name, value] : exchange.request.headers) {
        if (name == "cookie") value = Challenger::StripCookie(value);
      }
      std::erase_if(exchange.request.headers, [](const auto& header) {
        return header.first == "cookie" && header.second.empty();
      });
      if (exchange.request.path.starts_with(Challenger::kPathPrefix) &&
          !whoami) {
        HandleChallengeEndpoint(exchange, binding, now);
        return;
      }
    }
    if (context_.verdicts == nullptr) return;
    clearance_ = context_.challenger != nullptr
                     ? context_.challenger->FindClearance(exchange.observed,
                                                          binding, now)
                     : std::nullopt;
    session_ = clearance_ ? std::optional<std::string>(clearance_->session)
                          : std::nullopt;
    const std::string host = HostOnly(exchange.request.authority);
    const std::shared_ptr<const LabelPolicies> labels =
        context_.labels != nullptr ? context_.labels->snapshot() : nullptr;
    const HostMode mode = verdicts_->policy->ModeFor(
        host, labels ? labels->ModeFor(host) : std::nullopt);
    const LabelHostPolicy* label_policy =
        labels ? labels->PolicyFor(host) : nullptr;
    // "off": plain proxying, no verdicts and no limits.
    exchange.mode = HostModeName(mode);
    if (mode == HostMode::kOff) {
      if (whoami) RespondWhoami(exchange, host, mode, Verdict{}, false, {});
      return;
    }
    // Under-attack mode: counted before the verdict so a flood of any
    // class trips the automatic switch.
    bool under_attack = false;
    if (context_.attack != nullptr && context_.challenger != nullptr) {
      if (attack_prefix_.empty()) attack_prefix_ = IpPrefix(record_.peer);
      const AttackSubject subject{.host = host,
                                  .ip_prefix = attack_prefix_,
                                  .ja4 = record_.ja4,
                                  .asn = record_.asn};
      under_attack = context_.attack->Active(subject, now) ||
                     context_.attack->CountRequest(subject, now, SteadyNanos(),
                                                   context_.rate_limit_store);
    }
    const HttpRequest& request = exchange.observed;
    std::string pseudo;
    for (const std::string& name : request.pseudo_header_order) {
      if (!pseudo.empty()) pseudo.push_back(',');
      pseudo.push_back(name.size() > 1 ? name[1] : '?');
    }
    const std::string header_fp = HeaderOrderFingerprint(request);
    ScoringInput input;
    input.request = &request;
    input.ja4 = record_.ja4;
    input.offered_h2 = record_.offered_h2;
    input.quic = record_.quic;
    input.h2_fingerprint = exchange.h2_fingerprint;
    input.pseudo_order = pseudo;
    input.header_fp = header_fp;
    input.tcp_initial_ttl = record_.tcp_initial_ttl;
    input.tcp_rtt_us = record_.tcp_rtt_us;
    input.handshake_us = record_.handshake_us;
    Verdict verdict = verdicts_->scorer->Score(input);
    // Claimed crawlers: verified search engines skip scoring, fakes are
    // penalized, AI crawlers get their configured action.
    const KnownCrawler* crawler = FindCrawler(request.Header("user-agent"));
    bool verified_crawler = false;
    std::optional<Action> crawler_action;
    bool ai_robots = false;
    if (crawler != nullptr) {
      // Published IP ranges decide at once; reverse DNS otherwise.
      CrawlerStatus status = CrawlerStatus::kPending;
      bool decided_by_ranges = false;
      if (context_.crawler_ranges != nullptr) {
        status = CheckCrawlerRanges(
            *crawler, *context_.crawler_ranges->snapshot(), record_.peer);
        decided_by_ranges = status != CrawlerStatus::kPending;
        if (status == CrawlerStatus::kVerified) {
          GlobalMetrics().crawler_ranges_verified.Inc();
        } else if (status == CrawlerStatus::kFailed) {
          GlobalMetrics().crawler_ranges_failed.Inc();
        }
      }
      if (!decided_by_ranges && context_.crawler_verifier != nullptr &&
          !crawler->domains.empty()) {
        status = context_.crawler_verifier->Check(*crawler, record_.peer, now);
      }
      switch (status) {
        case CrawlerStatus::kVerified:
          verified_crawler = true;
          verdict.score = 0;
          verdict.bot_class = BotClass::kVerifiedBot;
          verdict.reasons = {std::format("verified_crawler:{}", crawler->id)};
          break;
        case CrawlerStatus::kFailed:
          verdict.score = std::min(
              100,
              verdict.score + verdicts_->scorer->SignalWeight("fake_crawler"));
          verdict.bot_class = verdicts_->scorer->Classify(verdict.score);
          verdict.reasons.push_back(
              std::format("fake_crawler:{}", crawler->id));
          break;
        case CrawlerStatus::kPending:
          break;
      }
      if (crawler->ai) {
        verdict.reasons.push_back(std::format("ai_crawler:{}", crawler->id));
        const std::string_view target = exchange.request.path;
        if (verdicts_->ai_robots &&
            target.substr(0, target.find('?')) == "/robots.txt" &&
            (exchange.request.method == "GET" ||
             exchange.request.method == "HEAD")) {
          ai_robots = true;
          verdict.reasons.emplace_back("ai_robots");
        }
        // botshield.ai_crawlers on the host's container beats crawlers.ai.
        crawler_action =
            label_policy != nullptr && label_policy->ai_crawlers_set
                ? label_policy->ai_crawlers
                : verdicts_->ai_crawler_action;
      }
    }
    // Web Bot Auth: a signature that verified with the agent's published
    // key. Trusted agents are verified bots; others are only recorded.
    if (context_.web_bot_auth != nullptr && !verified_crawler &&
        request.HasHeader("signature-input")) {
      const WebBotAuthResult signed_result =
          context_.web_bot_auth->Check(request, now);
      if (signed_result.status == WebBotAuthStatus::kVerified) {
        GlobalMetrics().signed_verified.Inc();
        exchange.signed_agent = signed_result.agent;
        if (std::ranges::any_of(
                verdicts_->trusted_agents, [&](const std::string& pattern) {
                  return HostMatches(pattern, signed_result.agent);
                })) {
          verified_crawler = true;
          verdict.score = 0;
          verdict.bot_class = BotClass::kVerifiedBot;
          verdict.reasons = {
              std::format("verified_agent:{}", signed_result.agent)};
        } else {
          verdict.reasons.push_back(
              std::format("signed_agent:{}", signed_result.agent));
        }
      } else if (signed_result.status == WebBotAuthStatus::kInvalid) {
        GlobalMetrics().signed_invalid.Inc();
        AddSignal("web_bot_auth_invalid", &verdict);
      }
    }
    // Clouds and hosters (ASN database).
    if (asn_hosting_ && !verified_crawler) {
      AddSignal("hosting_network", &verdict);
    }
    // Public reputation lists: the list for rules, its signal for the score.
    if (!verified_crawler) {
      for (const std::string& id : threat_lists_) {
        verdict.reasons.push_back("ip_list:" + id);
        if (const ThreatList* list = FindThreatList(id)) {
          AddSignal(list->signal, &verdict);
        }
      }
    }
    // Behaviour (5.4) and honeypot marks (6.3); verified crawlers crawl
    // regularly by nature and skip both.
    if (context_.behavior != nullptr && !verified_crawler) {
      ApplyBehavior(exchange, host, binding, label_policy, &verdict);
    }
    // Model signal; the feature vector also goes to the event (training).
    if (!verified_crawler &&
        (verdicts_->model != nullptr || context_.config->model_log_features)) {
      ApplyModel(exchange, &verdict);
    }
    // A solved challenge earns credit (behavioural signals stay).
    const bool token_valid = !verified_crawler &&
                             context_.challenger != nullptr &&
                             session_.has_value();
    const bool captcha_solved =
        token_valid && clearance_->level >= kTokenLevelCaptcha;
    if (token_valid) {
      GlobalMetrics().tokens_valid.Inc();
      verdict.score =
          std::max(0, verdict.score - context_.challenger->token_credit());
      verdict.bot_class = verdicts_->scorer->Classify(verdict.score);
      verdict.reasons.emplace_back("token_valid");
    }
    std::optional<Action> override_action;
    if (!verdicts_->rules.empty()) {
      override_action = ApplyRules(exchange, input, host, &verdict);
      // Score rules cannot turn a verified crawler into a scored client.
      if (verified_crawler) verdict.bot_class = BotClass::kVerifiedBot;
    }
    if (!override_action) override_action = crawler_action;
    // botshield.challenge.paths: a challenge there unless a rule decided.
    if (!override_action && label_policy != nullptr &&
        !label_policy->challenge_paths.empty()) {
      const std::string_view target = exchange.request.path;
      const std::string_view path = target.substr(0, target.find('?'));
      if (std::ranges::any_of(label_policy->challenge_paths,
                              [path](const std::string& glob) {
                                return GlobMatch(glob, path);
                              })) {
        override_action = Action::kChallenge;
        verdict.reasons.emplace_back("label:challenge_path");
      }
    }
    // Operational lists (admin API) beat rules and the class.
    if (context_.lists != nullptr) {
      ListMatchInput list_input;
      list_input.ip = record_.peer;
      list_input.ja4 = record_.ja4;
      list_input.header_fp = header_fp;
      list_input.host = host;
      list_input.now = UnixMillis() / 1000;
      if (const auto match = context_.lists->Match(list_input)) {
        override_action = match->action;
        verdict.reasons.push_back(std::format("list:{}", match->id));
      }
    }
    PolicyDecision decision =
        verdicts_->policy->Decide(verdict, mode, override_action);
    // Never challenge a client that already holds a valid token, nor show
    // a CAPTCHA to one who solved it.
    if ((token_valid && decision.would_action == Action::kChallenge) ||
        (captcha_solved && decision.would_action == Action::kCaptcha)) {
      decision.would_action = Action::kAllow;
      decision.action = Action::kAllow;
    }
    // Without a CAPTCHA configured, "captcha" falls back to the challenge.
    if (context_.captcha == nullptr) {
      if (decision.action == Action::kCaptcha) {
        decision.action = token_valid ? Action::kAllow : Action::kChallenge;
      }
      if (decision.would_action == Action::kCaptcha) {
        decision.would_action =
            token_valid ? Action::kAllow : Action::kChallenge;
      }
    }
    // Under attack every host challenges clients without a token, shadow
    // mode or not; explicit allows (rules, lists) and verified crawlers pass.
    if (under_attack && !token_valid && !verified_crawler &&
        override_action != Action::kAllow &&
        decision.action == Action::kAllow) {
      decision.action = Action::kChallenge;
      decision.would_action = Action::kChallenge;
      decision.enforce = true;
      verdict.reasons.emplace_back("under_attack");
      GlobalMetrics().attack_challenges.Inc();
    }

    exchange.score = verdict.score;
    exchange.bot_class = BotClassName(verdict.bot_class);
    exchange.reasons = verdict.reasons;
    exchange.action = ActionName(decision.action);
    exchange.would_action = ActionName(decision.would_action);
    if (whoami) {
      RespondWhoami(exchange, host, mode, verdict, token_valid, decision);
      return;
    }

    Metrics& metrics = GlobalMetrics();
    switch (verdict.bot_class) {
      case BotClass::kHuman:
        metrics.verdicts_human.Inc();
        break;
      case BotClass::kSuspicious:
        metrics.verdicts_suspicious.Inc();
        break;
      case BotClass::kBot:
        metrics.verdicts_bot.Inc();
        break;
      case BotClass::kVerifiedBot:
        metrics.verdicts_verified_bot.Inc();
        break;
    }

    std::string reasons;
    for (const std::string& reason : verdict.reasons) {
      if (!reasons.empty()) reasons.push_back(',');
      reasons += reason;
    }
    HeaderList& headers = exchange.request.headers;
    headers.emplace_back("x-bot-score", std::to_string(verdict.score));
    headers.emplace_back("x-bot-class", exchange.bot_class);
    headers.emplace_back("x-bot-reasons", reasons.empty() ? "-" : reasons);
    headers.emplace_back("x-bot-mode", HostModeName(mode));

    // Before any block: a polite AI crawler that reads it goes away.
    if (ai_robots) {
      exchange.RespondLocally(200, kAiRobotsTxt,
                              {{"cache-control", "max-age=3600"}},
                              "text/plain; charset=utf-8");
      return;
    }
    if (decision.action == Action::kBlock) {
      metrics.requests_blocked.Inc();
      exchange.RespondLocally(verdicts_->policy->block_status(),
                              "request blocked\n");
      return;
    }
    if (decision.would_action == Action::kBlock) {
      metrics.requests_would_block.Inc();
    }
    if (decision.action == Action::kChallenge &&
        context_.challenger != nullptr) {
      metrics.challenges_issued.Inc();
      if (IsNavigation(request)) {
        exchange.RespondLocally(
            403,
            context_.challenger->Page(
                binding, context_.challenger->DifficultyFor(verdict.bot_class),
                exchange.request.path, now),
            {{"cache-control", "no-store"}}, "text/html; charset=utf-8");
      } else {
        const nlohmann::json body = {
            {"error", "challenge_required"},
            {"challenge",
             std::format("{}challenge?r={}", Challenger::kPathPrefix,
                         PercentEncode(exchange.request.path))}};
        exchange.RespondLocally(403, body.dump() + "\n", {},
                                "application/json");
      }
      return;
    }
    if (decision.would_action == Action::kChallenge) {
      metrics.challenges_would.Inc();
    }
    if (decision.action == Action::kCaptcha && context_.captcha != nullptr) {
      metrics.captchas_issued.Inc();
      if (IsNavigation(request)) {
        exchange.RespondLocally(
            403,
            context_.captcha->Page(binding, exchange.request.path,
                                   UnixMillis()),
            {{"cache-control", "no-store"}}, "text/html; charset=utf-8");
      } else {
        const nlohmann::json body = {
            {"error", "captcha_required"},
            {"captcha", std::format("{}captcha?r={}", Challenger::kPathPrefix,
                                    PercentEncode(exchange.request.path))}};
        exchange.RespondLocally(403, body.dump() + "\n", {},
                                "application/json");
      }
      return;
    }
    if (decision.action == Action::kTarpit) {
      const Config& config = *context_.config;
      TarpitSettings tarpit;
      tarpit.duration = config.tarpit_duration;
      tarpit.interval = config.tarpit_interval;
      tarpit.chunk = config.tarpit_chunk;
      tarpit.max_active = config.tarpit_max_active;
      if (executor_ &&
          StartTarpit(executor_, exchange.shared_from_this(), tarpit)) {
        metrics.tarpits.Inc();
        return;
      }
      // Too many at once: a plain block costs nothing.
      metrics.tarpit_overflow.Inc();
      metrics.requests_blocked.Inc();
      exchange.RespondLocally(verdicts_->policy->block_status(),
                              "request blocked\n");
      return;
    }
    if (decision.action == Action::kDecoy) {
      metrics.decoys.Inc();
      exchange.watermark =
          DecoyWatermark(context_.challenger != nullptr
                             ? context_.challenger->watermark_secret()
                             : std::string_view(record_.server_name),
                         exchange.request_id);
      const bool html = IsNavigation(request);
      const std::string_view target = exchange.request.path;
      exchange.RespondLocally(
          200,
          html && context_.config->decoy_labyrinth
              ? RenderLabyrinth(context_.challenger != nullptr
                                    ? context_.challenger->watermark_secret()
                                    : std::string_view(record_.server_name),
                                target.substr(0, target.find('?')),
                                exchange.watermark)
              : RenderDecoy(html ? context_.config->decoy_html
                                 : context_.config->decoy_json,
                            html, exchange.watermark),
          {{"cache-control", "no-store"}},
          html ? "text/html; charset=utf-8" : "application/json");
      return;
    }
    // An allow rule (monitoring, partners) also bypasses rate limits.
    if (override_action != Action::kAllow) {
      CheckRateLimits(exchange, verdict, host, decision, labels.get());
    }
  }

  // Adds a library signal (when its weight is positive) to the verdict.
  void AddSignal(std::string_view signal, Verdict* verdict) const {
    const int weight = verdicts_->scorer->SignalWeight(signal);
    if (weight <= 0) return;
    verdict->score = std::min(100, verdict->score + weight);
    verdict->reasons.emplace_back(signal);
    verdict->bot_class = verdicts_->scorer->Classify(verdict->score);
  }

  void ApplyModel(Exchange& exchange, Verdict* verdict) const {
    FeatureInput input;
    input.request = &exchange.observed;
    input.path = exchange.request.path;
    input.ja4 = record_.ja4;
    input.http2 = !exchange.h2_fingerprint.empty();
    input.offered_h2 = record_.offered_h2;
    input.tcp_initial_ttl = record_.tcp_initial_ttl;
    input.reasons = verdict->reasons;
    const std::array<float, kFeatureCount> features = ExtractFeatures(input);
    if (context_.config->model_log_features) {
      exchange.features.assign(features.begin(), features.end());
    }
    if (verdicts_->model == nullptr) return;
    exchange.model_score = verdicts_->model->Predict(features);
    if (exchange.model_score < verdicts_->model_threshold) return;
    const int weight = verdicts_->scorer->SignalWeight("model");
    if (weight <= 0) return;
    GlobalMetrics().model_flags.Inc();
    verdict->score = std::min(100, verdict->score + weight);
    verdict->reasons.emplace_back("model");
    verdict->bot_class = verdicts_->scorer->Classify(verdict->score);
  }

  void ApplyBehavior(Exchange& exchange, std::string_view host,
                     const ClientBinding& binding,
                     const LabelHostPolicy* label_policy,
                     Verdict* verdict) const {
    const HttpRequest& request = exchange.observed;
    const int64_t now_ms = SteadyMillis();
    const std::string_view target = exchange.request.path;
    const std::string_view path = target.substr(0, target.find('?'));
    // Behavior and honeypot marks follow the exact JA4, not the coarser
    // clearance binding: one browser family behind a /24 is many clients.
    const std::string ja4_hash =
        record_.ja4.empty() ? std::string(8, '-') : Sha256Hex(record_.ja4, 8);
    exchange.behavior_client =
        std::format("{}|{}|{}", host, ja4_hash, binding.ip_hash);
    const std::vector<std::string> trap_keys = {
        "ip|" + record_.peer.to_string(),
        std::format("fp|{}|{}", ja4_hash, binding.ip_hash)};
    std::vector<std::string> signals;
    const Config& config = *context_.config;
    const auto matches = [path](const std::vector<std::string>& globs) {
      return std::ranges::any_of(globs, [path](const std::string& glob) {
        return GlobMatch(glob, path);
      });
    };
    if (matches(verdicts_->honeypot_paths) ||
        (label_policy != nullptr && matches(label_policy->honeypot_paths))) {
      GlobalMetrics().honeypot_hits.Inc();
      signals.emplace_back("honeypot");
      context_.behavior->Trap(trap_keys, now_ms,
                              now_ms + config.honeypot_ttl.count());
      if (context_.xdp_blocks != nullptr) {
        context_.xdp_blocks->Add(
            record_.peer, UnixMillis() / 1000 +
                              std::chrono::duration_cast<std::chrono::seconds>(
                                  config.honeypot_ttl)
                                  .count());
      }
    } else if (context_.behavior->Trapped(trap_keys, now_ms)) {
      signals.emplace_back("honeypot_client");
    }
    context_.behavior->OnRequest(
        exchange.behavior_client, host,
        ClassifyRequest(request.method, path, request.Header("sec-fetch-mode"),
                        request.Header("sec-fetch-dest"),
                        request.Header("accept"),
                        request.Header("x-requested-with")),
        now_ms, &signals);
    int added = 0;
    for (std::string& signal : signals) {
      const int weight = verdicts_->scorer->SignalWeight(signal);
      if (weight <= 0) continue;
      verdict->score = std::min(100, verdict->score + weight);
      verdict->reasons.push_back(std::move(signal));
      ++added;
    }
    if (added > 0) {
      GlobalMetrics().behavior_signals.Inc(added);
      verdict->bot_class = verdicts_->scorer->Classify(verdict->score);
    }
  }

  // A third-party CAPTCHA answer: the provider's siteverify runs on the
  // CAPTCHA's threads; the response follows on this connection's loop.
  void VerifyWidget(Exchange& exchange, const ClientBinding& binding,
                    std::string_view query) const {
    const auto finish = [](Exchange& target, const Captcha::Verdict& verdict) {
      Metrics& metrics = GlobalMetrics();
      target.client_fp = verdict.client_fp;
      target.reasons = {"captcha:" + verdict.reason};
      if (verdict.passed) {
        metrics.captchas_passed.Inc();
        target.action = "allow";
        target.RespondLocally(302, "",
                              {{"location", verdict.return_path},
                               {"set-cookie", verdict.set_cookie},
                               {"cache-control", "no-store"}});
      } else {
        metrics.captchas_failed.Inc();
        target.action = "block";
        target.RespondLocally(403, ChallengeFailedPage(),
                              {{"cache-control", "no-store"}},
                              "text/html; charset=utf-8");
      }
    };
    Captcha::Verdict immediate;
    const std::shared_ptr<Exchange> self = exchange.shared_from_this();
    const asio::any_io_executor executor = executor_;
    const bool queued =
        executor &&
        context_.captcha->VerifyWidget(
            query, binding, exchange.observed.Header("user-agent"),
            HostOnly(exchange.request.authority),
            Unmapped(record_.peer).to_string(), UnixMillis(), &immediate,
            [self, executor, finish](Captcha::Verdict verdict) {
              asio::post(executor,
                         [self, finish, verdict = std::move(verdict)] {
                           if (!self->client_cancelled) finish(*self, verdict);
                         });
            });
    if (queued) {
      exchange.DeferLocalResponse();
      return;
    }
    if (immediate.reason.empty()) immediate.reason = "failed:unavailable";
    finish(exchange, immediate);
  }

  // The /__bs/* endpoints are answered here, so the request rate limits
  // never see them: a per-address limit of their own. False when over it
  // (429 sent).
  bool ChallengeEndpointAllowed(Exchange& exchange) const {
    const Config& config = *context_.config;
    const GcraResult allowed = context_.rate_limit_store->Check(
        "bs\x1f" + Unmapped(record_.peer).to_string(),
        GcraParams::FromRate(
            config.challenge_endpoint_rate,
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                config.challenge_endpoint_period)
                .count(),
            config.challenge_endpoint_burst),
        SteadyNanos());
    if (allowed.allowed) return true;
    GlobalMetrics().challenge_endpoint_limited.Inc();
    exchange.action = "rate_limit";
    exchange.rate_limit = "challenge_endpoint";
    exchange.RespondLocally(
        429, "too many requests\n",
        {{"retry-after",
          std::to_string(RetryAfterSeconds(allowed.retry_after_ns))},
         {"cache-control", "no-store"}});
    return false;
  }

  // `whoami: true` in the current verdict set (reloadable).
  bool WhoamiEnabled() const {
    if (context_.verdicts == nullptr) return false;
    const std::shared_ptr<const VerdictSet> verdicts =
        context_.verdicts->snapshot();
    return verdicts != nullptr && verdicts->config != nullptr &&
           verdicts->config->whoami;
  }

  // What a reason added to the score: the library weight of the signal (or
  // of its prefix), an automation signature's own weight, the token
  // credit (negative); 0 for reasons that only record.
  int ReasonWeight(std::string_view reason) const {
    if (reason == "token_valid") {
      return context_.challenger != nullptr
                 ? -context_.challenger->token_credit()
                 : 0;
    }
    const FingerprintLibrary& library = *verdicts_->library;
    if (reason.starts_with("known_automation:")) {
      const std::string_view id = reason.substr(17);
      for (const AutomationSignature& signature : library.automation()) {
        if (signature.id == id) return signature.weight;
      }
      return 0;
    }
    if (const int weight = library.Weight(reason); weight != 0) return weight;
    return library.Weight(reason.substr(0, reason.find(':')));
  }

  // Answers /__bs/whoami with the verdict instead of acting on it. The
  // event records it as allowed, with the would-be action and reason
  // "whoami".
  void RespondWhoami(Exchange& exchange, const std::string& host, HostMode mode,
                     const Verdict& verdict, bool token_valid,
                     const PolicyDecision& decision) const {
    const HttpRequest& request = exchange.observed;
    const UserAgent ua = ParseUserAgent(request.Header("user-agent"));
    WhoamiReport report;
    report.request_id = exchange.request_id;
    report.host = host;
    report.mode = HostModeName(mode);
    report.ip = Unmapped(record_.peer).to_string();
    report.ip_prefix = IpPrefix(record_.peer);
    report.asn = record_.asn;
    report.asn_org = asn_org_;
    report.hosting = asn_hosting_;
    report.user_agent = std::string(request.Header("user-agent"));
    report.claimed_family = ua.family;
    report.claimed_major = ua.major;
    report.claimed_os = ua.os;
    report.claimed_tool = ua.tool;
    report.claims_crawler = ua.claims_crawler;
    report.headless = ua.headless;
    report.http_version = record_.quic ? "3" : request.version;
    report.offered_h2 = record_.offered_h2;
    report.ja4 = record_.ja4;
    report.h2_fingerprint = exchange.h2_fingerprint;
    for (const std::string& name : request.pseudo_header_order) {
      if (!report.pseudo_order.empty()) report.pseudo_order.push_back(',');
      report.pseudo_order.push_back(name.size() > 1 ? name[1] : '?');
    }
    report.header_fp = HeaderOrderFingerprint(request);
    report.tcp_initial_ttl = record_.tcp_initial_ttl;
    report.tcp_rtt_us = record_.tcp_rtt_us;
    report.handshake_us = record_.handshake_us;
    if (verdicts_ != nullptr) {
      report.tls_engines = MatchingTlsEngines(*verdicts_->library, record_.ja4);
    }
    if (mode != HostMode::kOff) {
      report.score = verdict.score;
      report.bot_class = std::string(BotClassName(verdict.bot_class));
      for (const std::string& reason : verdict.reasons) {
        report.reasons.emplace_back(reason, ReasonWeight(reason));
      }
      report.token_valid = token_valid;
      report.action = std::string(ActionName(decision.action));
      report.would_action = std::string(ActionName(decision.would_action));
    }
    exchange.mode = "whoami";
    exchange.action = "allow";
    exchange.reasons.emplace_back("whoami");
    std::string_view content_type = "text/plain; charset=utf-8";
    std::string body;
    const std::string_view target = exchange.request.path;
    const std::size_t question = target.find('?');
    switch (ChooseWhoamiFormat(question == std::string_view::npos
                                   ? std::string_view()
                                   : target.substr(question + 1),
                               request.Header("accept"))) {
      case WhoamiFormat::kJson:
        content_type = "application/json";
        body = RenderWhoamiJson(report);
        break;
      case WhoamiFormat::kHtml:
        content_type = "text/html; charset=utf-8";
        body = RenderWhoamiHtml(report);
        break;
      case WhoamiFormat::kText:
        body = RenderWhoamiText(report);
        break;
    }
    exchange.RespondLocally(200, std::move(body),
                            {{"cache-control", "no-store"},
                             {"content-security-policy",
                              "default-src 'none'; style-src 'unsafe-inline'"}},
                            content_type);
  }

  // /__bs/challenge?r=<path> (page) and /__bs/verify (solution).
  void HandleChallengeEndpoint(Exchange& exchange, const ClientBinding& binding,
                               int64_t now) const {
    const std::string_view target = exchange.request.path;
    const std::size_t question = target.find('?');
    const std::string_view path = target.substr(0, question);
    const std::string_view query = question == std::string_view::npos
                                       ? std::string_view()
                                       : target.substr(question + 1);
    exchange.mode = "challenge";
    Metrics& metrics = GlobalMetrics();
    const Config& config = *context_.config;
    if (!ChallengeEndpointAllowed(exchange)) return;
    if (path == "/__bs/verify") {
      const Challenger::Result result = context_.challenger->Verify(
          query, binding, exchange.observed.Header("user-agent"), now);
      exchange.client_fp = result.client_fp;
      const bool escalate = result.escalate && context_.captcha != nullptr &&
                            config.captcha_escalate;
      if (escalate) {
        // Suspicious or unusual: the CAPTCHA decides instead of a token.
        metrics.challenge_escalations.Inc();
        metrics.captchas_issued.Inc();
        exchange.reasons = {"challenge:escalated:" + (result.passed
                                                          ? result.soft.front()
                                                          : result.reason)};
        exchange.action = "captcha";
        exchange.RespondLocally(
            403,
            context_.captcha->Page(binding, result.return_path, UnixMillis()),
            {{"cache-control", "no-store"}}, "text/html; charset=utf-8");
      } else if (result.passed) {
        metrics.challenges_passed.Inc();
        exchange.reasons = {"challenge:passed"};
        for (const std::string& soft : result.soft) {
          exchange.reasons.push_back("challenge:soft:" + soft);
        }
        exchange.action = "allow";
        exchange.RespondLocally(302, "",
                                {{"location", result.return_path},
                                 {"set-cookie", result.set_cookie},
                                 {"cache-control", "no-store"}});
      } else {
        metrics.challenges_failed.Inc();
        exchange.reasons = {"challenge:failed:" + result.reason};
        exchange.action = "block";
        exchange.RespondLocally(403, ChallengeFailedPage(),
                                {{"cache-control", "no-store"}},
                                "text/html; charset=utf-8");
      }
      return;
    }
    if (path == "/__bs/challenge") {
      const std::string return_path = QueryParam(ParseQuery(query), "r");
      exchange.RespondLocally(
          200,
          context_.challenger->Page(
              binding,
              context_.challenger->DifficultyFor(BotClass::kSuspicious),
              return_path, now),
          {{"cache-control", "no-store"}}, "text/html; charset=utf-8");
      return;
    }
    if (context_.captcha != nullptr && path == "/__bs/captcha") {
      metrics.captchas_issued.Inc();
      exchange.RespondLocally(
          200,
          context_.captcha->Page(binding, QueryParam(ParseQuery(query), "r"),
                                 UnixMillis()),
          {{"cache-control", "no-store"}}, "text/html; charset=utf-8");
      return;
    }
    if (context_.captcha != nullptr && path == "/__bs/captcha/answer") {
      Captcha::Answer answer = context_.captcha->AnswerPuzzle(
          query, binding, exchange.observed.Header("user-agent"), UnixMillis());
      exchange.client_fp = answer.client_fp;
      exchange.reasons = {"captcha:" + answer.outcome};
      HeaderList headers = {{"cache-control", "no-store"}};
      if (!answer.set_cookie.empty()) {
        metrics.captchas_passed.Inc();
        exchange.action = "allow";
        headers.emplace_back("set-cookie", answer.set_cookie);
      } else if (answer.outcome.starts_with("failed")) {
        metrics.captchas_failed.Inc();
        exchange.action = "block";
      } else {
        exchange.action = "captcha";
      }
      exchange.RespondLocally(answer.outcome.starts_with("failed") ? 403 : 200,
                              answer.body, headers, "application/json");
      return;
    }
    if (context_.captcha != nullptr && path == "/__bs/captcha/verify") {
      VerifyWidget(exchange, binding, query);
      return;
    }
    exchange.RespondLocally(404, "not found\n");
  }

  // Counts the request against the matching rate limits. Over a limit:
  // 429 when the host is enforced, otherwise only recorded.
  void CheckRateLimits(Exchange& exchange, const Verdict& verdict,
                       std::string_view host, const PolicyDecision& decision,
                       const LabelPolicies* labels) {
    const bool configured = !verdicts_->rate_limits.empty();
    const bool labelled = labels != nullptr && !labels->rate_limits().empty();
    // Action "throttle": the throttle limit applies on top of the others.
    const bool throttled = decision.would_action == Action::kThrottle &&
                           !verdicts_->throttle.empty();
    if (!configured && !labelled && !throttled) return;
    const std::string_view path_and_query = exchange.request.path;
    RateLimitRequest request;
    request.request = &exchange.observed;
    request.ip = record_.peer;
    request.host = host;
    request.path = path_and_query.substr(0, path_and_query.find('?'));
    request.method = exchange.request.method;
    request.bot_class = BotClassName(verdict.bot_class);
    request.ja4 = record_.ja4;
    request.h2_fingerprint = exchange.h2_fingerprint;
    if (session_) request.session = *session_;
    request.asn = record_.asn;
    const int64_t now = SteadyNanos();
    std::optional<RateLimitHit> hit;
    if (throttled) {
      hit = verdicts_->throttle.Check(request, context_.rate_limit_store, now);
    }
    // Limits on origin responses (statuses): counted in OnProxyDone.
    std::vector<ResponseCount> counts;
    if (configured) {
      std::optional<RateLimitHit> limit_hit = verdicts_->rate_limits.Check(
          request, context_.rate_limit_store, now, &counts);
      if (!hit) hit = std::move(limit_hit);
    }
    if (labelled) {
      // Label limits count the request too; the first refusal is reported.
      std::optional<RateLimitHit> label_hit = labels->rate_limits().Check(
          request, context_.rate_limit_store, now, &counts);
      if (!hit) hit = std::move(label_hit);
    }
    if (!counts.empty()) {
      response_counts_.insert_or_assign(exchange.request_id, std::move(counts));
    }
    if (!hit) return;

    exchange.rate_limit = hit->name;
    Metrics& metrics = GlobalMetrics();
    if (!decision.enforce) {
      metrics.rate_limited_shadow.Inc();
      if (decision.would_action == Action::kAllow) {
        exchange.would_action = "rate_limit";
      }
      return;
    }
    metrics.rate_limited.Inc();
    exchange.action = "rate_limit";
    exchange.would_action = "rate_limit";
    const int64_t retry_after = RetryAfterSeconds(hit->result.retry_after_ns);
    exchange.RespondLocally(
        429, "too many requests\n",
        {{"retry-after", std::to_string(retry_after)},
         {"ratelimit-policy", std::format(R"("{}";q={};w={})", hit->name,
                                          hit->burst, hit->window_seconds)},
         {"ratelimit",
          std::format(R"("{}";r=0;t={})", hit->name, retry_after)}});
  }

  // Score rules adjust the verdict, then the first allow/block rule may
  // override the action. Matches are added to the reasons as "rule:<name>".
  std::optional<Action> ApplyRules(const Exchange& exchange,
                                   const ScoringInput& input,
                                   std::string_view host,
                                   Verdict* verdict) const {
    const HttpRequest& request = exchange.observed;
    const UserAgent ua = ParseUserAgent(request.Header("user-agent"));
    const std::string_view path_and_query = exchange.request.path;
    RuleContext rules;
    rules.request = &request;
    rules.ip = record_.peer;
    rules.host = host;
    rules.path = path_and_query.substr(0, path_and_query.find('?'));
    rules.sni = record_.server_name;
    rules.alpn = record_.alpn;
    rules.ja4 = input.ja4;
    rules.h2_fingerprint = input.h2_fingerprint;
    rules.pseudo_order = input.pseudo_order;
    rules.header_fp = input.header_fp;
    rules.tcp_fingerprint = record_.tcp_fingerprint;
    rules.ua_family = ua.family;
    rules.ua_engine = ua.engine;
    rules.ua_os = ua.os;
    rules.ua_tool = ua.tool;
    rules.score = verdict->score;
    rules.bot_class = BotClassName(verdict->bot_class);
    rules.reasons = &verdict->reasons;
    rules.asn = record_.asn;
    rules.asn_org = asn_org_;
    rules.asn_country = asn_country_;
    rules.asn_hosting = asn_hosting_;
    rules.signed_agent = exchange.signed_agent;
    rules.tcp_rtt_ms = record_.tcp_rtt_us < 0 ? -1 : record_.tcp_rtt_us / 1000;
    rules.handshake_ms =
        record_.handshake_us < 0 ? -1 : record_.handshake_us / 1000;

    std::vector<std::string> matched;
    const int delta = verdicts_->rules.ScoreDelta(rules, &matched);
    if (delta != 0) {
      verdict->score = std::clamp(verdict->score + delta, 0, 100);
      verdict->bot_class = verdicts_->scorer->Classify(verdict->score);
      rules.score = verdict->score;
      rules.bot_class = BotClassName(verdict->bot_class);
    }
    const std::optional<Action> action =
        verdicts_->rules.Decide(rules, &matched);
    GlobalMetrics().rules_matched.Inc(matched.size());
    for (const std::string& name : matched) {
      verdict->reasons.push_back("rule:" + name);
    }
    return action;
  }

  void OnProxyDone(const Exchange& exchange) {
    ++record_.requests;
    if (const auto it = response_counts_.find(exchange.request_id);
        it != response_counts_.end()) {
      // Only the origin's answers count: the gateway's own 403 and 429
      // would otherwise feed the limit that produced them.
      if (exchange.response_started && !exchange.local) {
        CountResponse(it->second, exchange.response.status,
                      context_.rate_limit_store, SteadyNanos());
      }
      response_counts_.erase(it);
    }
    GlobalMetrics().http_requests_observed.Inc();
    if (!exchange.h2_fingerprint.empty()) {
      record_.h2_fingerprint = exchange.h2_fingerprint;
    }
    if (context_.decisions != nullptr) RecordDecision(exchange);
    if (context_.behavior != nullptr && !exchange.behavior_client.empty() &&
        exchange.response_started) {
      context_.behavior->OnStatus(exchange.behavior_client,
                                  exchange.response.status, SteadyMillis());
    }
    if (context_.events == nullptr || !context_.event_settings->requests) {
      return;
    }
    RequestOutcome outcome;
    outcome.status = exchange.response_started ? exchange.response.status : 0;
    outcome.duration_ms = SteadyMillis() - exchange.started_ms;
    outcome.response_bytes = exchange.response_bytes;
    outcome.local = exchange.local;
    outcome.score = exchange.score;
    outcome.bot_class = exchange.bot_class;
    outcome.reasons = exchange.reasons;
    outcome.action = exchange.action;
    outcome.would_action = exchange.would_action;
    outcome.rate_limit = exchange.rate_limit;
    outcome.request_id = exchange.request_id;
    outcome.watermark = exchange.watermark;
    outcome.features = exchange.features;
    outcome.model_score = exchange.model_score;
    outcome.client_fp = exchange.client_fp;
    outcome.signed_agent = exchange.signed_agent;
    try {
      context_.events->Publish(
          "req",
          RequestEventJson(record_, exchange.observed, record_.requests,
                           *context_.event_settings, UnixMillis(), &outcome));
    } catch (const std::exception& e) {
      log::Warn("conn={} request event dropped: {}", record_.id, e.what());
    }
  }

 private:
  void RecordDecision(const Exchange& exchange) const {
    const HttpRequest& request = exchange.observed;
    DecisionRecord record;
    record.request_id = exchange.request_id;
    record.time_ms = UnixMillis();
    record.host = HostOnly(exchange.request.authority);
    record.method = request.method;
    record.path_group = PathGroup(request.target);
    record.ip = Unmapped(record_.peer).to_string();
    record.user_agent = std::string(request.Header("user-agent"));
    record.ja4 = record_.ja4;
    record.h2_fingerprint = exchange.h2_fingerprint;
    record.header_fp = HeaderOrderFingerprint(request);
    record.mode = exchange.mode;
    record.score = exchange.score;
    record.bot_class = exchange.bot_class;
    record.reasons = exchange.reasons;
    record.action = exchange.action;
    record.would_action = exchange.would_action;
    record.rate_limit = exchange.rate_limit;
    record.status = exchange.response_started ? exchange.response.status : 0;
    record.local = exchange.local;
    record.duration_ms = SteadyMillis() - exchange.started_ms;
    context_.decisions->Add(std::move(record));
  }

  void OnRequest(HttpRequest&& request) {
    ++record_.requests;
    GlobalMetrics().http_requests_observed.Inc();
    try {
      context_.events->Publish(
          "req", RequestEventJson(record_, request, record_.requests,
                                  *context_.event_settings, UnixMillis()));
    } catch (const std::exception& e) {
      log::Warn("conn={} request event dropped: {}", record_.id, e.what());
    }
  }

  const GatewayContext& context_;
  ConnectionRecord record_;
  std::unique_ptr<H1Tap> h1_;
  PendingSlot* pending_slot_ = nullptr;
  // Verdict snapshot of the request being decided (OnProxyRequest).
  std::shared_ptr<const VerdictSet> verdicts_;
  // Its clearance token, if any (session id and level).
  std::optional<Clearance> clearance_;
  std::optional<std::string> session_;
  // Response-counting limits of the requests in flight, by request id;
  // settled in OnProxyDone.
  std::unordered_map<std::string, std::vector<ResponseCount>> response_counts_;
  // From the ASN database (LookupAsn).
  std::string asn_org_;
  std::string asn_country_;
  bool asn_hosting_ = false;
  // Ids of the reputation lists holding the client (LookupThreatLists).
  std::vector<std::string> threat_lists_;
  // The client's network as in events, for attack signatures.
  std::string attack_prefix_;
  asio::any_io_executor executor_;
  int request_sequence_ = 0;
};

template <typename Socket>
void CloseQuietly(Socket& socket) {
  std::error_code ec;
  socket.close(ec);
}

void ShutdownSend(tcp::socket& socket) {
  std::error_code ec;
  socket.shutdown(tcp::socket::shutdown_send, ec);
}

void SetNoDelay(tcp::socket& socket) {
  std::error_code ec;
  socket.set_option(tcp::no_delay(true), ec);
}

std::string SelectedAlpn(const SSL* ssl) {
  const uint8_t* data = nullptr;
  unsigned size = 0;
  SSL_get0_alpn_selected(ssl, &data, &size);
  return {reinterpret_cast<const char*>(data), size};
}

void CountRoute(const RouteDecision& decision) {
  Metrics& metrics = GlobalMetrics();
  switch (decision.reason) {
    case RouteReason::kCertificate:
      metrics.route_terminate.Inc();
      break;
    case RouteReason::kAcmeTlsAlpn:
      metrics.route_passthrough_acme_tls_alpn.Inc();
      break;
    case RouteReason::kNoServerName:
      if (decision.route == Route::kPassthrough) {
        metrics.route_passthrough_no_server_name.Inc();
      } else {
        metrics.rejected_no_server_name.Inc();
      }
      break;
    case RouteReason::kPassthroughPolicy:
      metrics.route_passthrough_policy.Inc();
      break;
    case RouteReason::kNoCertificate:
      metrics.route_passthrough_no_certificate.Inc();
      break;
    case RouteReason::kNotTls:
      if (decision.route == Route::kPassthrough) {
        metrics.route_passthrough_not_tls.Inc();
      } else {
        metrics.rejected_not_tls.Inc();
      }
      break;
    case RouteReason::kInvalidHello:
      metrics.rejected_invalid_hello.Inc();
      break;
  }
}

// Copies `from` -> `to` until EOF or error. Every read touches the idle
// watchdog; `on_data` sees each chunk after it was forwarded. `on_eof` runs
// on a clean end of stream, `on_error` on failures.
template <typename From, typename To, typename OnData, typename OnEof,
          typename OnError>
asio::awaitable<void> Pump(From& from, To& to, Watchdog& watchdog,
                           OnData on_data, OnEof on_eof, OnError on_error) {
  std::vector<uint8_t> buffer(kPumpBufferSize);
  while (true) {
    auto [read_ec, n] =
        co_await from.async_read_some(asio::buffer(buffer), kUse);
    if (n > 0) {
      watchdog.Touch();
      auto [write_ec, written] =
          co_await asio::async_write(to, asio::buffer(buffer.data(), n), kUse);
      if (write_ec) {
        on_error();
        co_return;
      }
      on_data(std::span<const uint8_t>(buffer.data(), written));
    }
    if (read_ec) {
      if (read_ec == asio::error::eof) {
        on_eof();
      } else {
        on_error();
      }
      co_return;
    }
  }
}

// Bidirectional TCP relay with half-close support.
asio::awaitable<void> RelayTcp(tcp::socket& client, tcp::socket& upstream,
                               const Config& config,
                               ConnectionObserver& observer) {
  auto executor = co_await asio::this_coro::executor;
  Metrics& metrics = GlobalMetrics();
  auto close_both = [&client, &upstream] {
    CloseQuietly(client);
    CloseQuietly(upstream);
  };
  ScopedWatchdog idle(executor, config.idle_timeout, [&metrics, close_both] {
    metrics.idle_timeouts.Inc();
    close_both();
  });
  auto on_client_data = [&observer](std::span<const uint8_t> data) {
    observer.OnClientData(data);
  };
  auto on_upstream_data = [&observer](std::span<const uint8_t> data) {
    observer.OnUpstreamData(data);
  };
  co_await (Pump(
                client, upstream, *idle, on_client_data,
                [&upstream] { ShutdownSend(upstream); }, close_both) &&
            Pump(
                upstream, client, *idle, on_upstream_data,
                [&client] { ShutdownSend(client); }, close_both));
}

// Connects to Traefik and sends the PROXY header if enabled.
asio::awaitable<std::optional<tcp::socket>> ConnectUpstream(
    const tcp::endpoint& endpoint, const ConnectionInfo& info,
    std::string_view authority, const Config& config) {
  auto executor = co_await asio::this_coro::executor;
  tcp::socket socket(executor);
  {
    ScopedWatchdog deadline(executor, config.upstream_connect_timeout,
                            [&socket] { CloseQuietly(socket); });
    auto [ec] = co_await socket.async_connect(endpoint, kUse);
    if (ec) {
      GlobalMetrics().upstream_connect_failures.Inc();
      log::Warn("conn={} upstream connect to {} failed: {}", info.id,
                FormatEndpoint(endpoint),
                deadline->expired() ? "timeout" : ec.message());
      co_return std::nullopt;
    }
  }
  SetNoDelay(socket);
  if (config.proxy_protocol) {
    const std::vector<uint8_t> header =
        EncodeProxyV2(info.peer, info.local, authority);
    auto [ec, n] =
        co_await asio::async_write(socket, asio::buffer(header), kUse);
    if (ec) {
      log::Warn("conn={} sending PROXY header failed: {}", info.id,
                ec.message());
      co_return std::nullopt;
    }
  }
  co_return std::optional<tcp::socket>(std::move(socket));
}

asio::awaitable<void> RunPassthrough(tcp::socket client,
                                     std::vector<uint8_t> prefix,
                                     const tcp::endpoint& upstream_endpoint,
                                     const ConnectionInfo& info,
                                     std::string_view authority,
                                     const GatewayContext& context,
                                     ConnectionObserver& observer) {
  std::optional<tcp::socket> upstream = co_await ConnectUpstream(
      upstream_endpoint, info, authority, *context.config);
  if (!upstream) co_return;
  if (!prefix.empty()) {
    auto [ec, n] =
        co_await asio::async_write(*upstream, asio::buffer(prefix), kUse);
    if (ec) co_return;
    observer.OnClientData(std::span<const uint8_t>(prefix.data(), n));
  }
  co_await RelayTcp(client, *upstream, *context.config, observer);
}

asio::awaitable<void> RunTerminate(tcp::socket socket,
                                   std::vector<uint8_t> prefix,
                                   std::shared_ptr<const CertEntry> certificate,
                                   std::string server_name,
                                   const ConnectionInfo& info,
                                   const GatewayContext& context,
                                   ConnectionObserver& observer) {
  const Config& config = *context.config;
  Metrics& metrics = GlobalMetrics();
  auto executor = co_await asio::this_coro::executor;

  ClientTlsStream client(
      PrefixedStream<tcp::socket>(std::move(socket), std::move(prefix)),
      *certificate->context);
  {
    ScopedWatchdog deadline(executor, config.tls_handshake_timeout,
                            [&client] { CloseQuietly(client.lowest_layer()); });
    const auto started = std::chrono::steady_clock::now();
    auto [ec] =
        co_await client.async_handshake(asio::ssl::stream_base::server, kUse);
    if (ec) {
      metrics.tls_handshake_failures_client.Inc();
      log::Debug("conn={} client handshake failed: {}", info.id,
                 deadline->expired() ? "timeout" : ec.message());
      co_return;
    }
    // The ClientHello was already read: from here the handshake is our
    // flight and the client's Finished, one round trip in TLS 1.3.
    if (SSL_version(client.native_handle()) == TLS1_3_VERSION) {
      observer.record().handshake_us =
          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now() - started)
              .count();
    }
    observer.record().tcp_rtt_us =
        TcpRttMicros(client.lowest_layer().native_handle());
  }
  const std::string alpn = SelectedAlpn(client.native_handle());
  observer.record().alpn = alpn;

  ClientInfo client_info;
  client_info.address = info.peer.address();
  client_info.local_port = info.local.port();
  client_info.server_name = std::move(server_name);
  ProxyHooks hooks;
  hooks.on_request = [&observer](Exchange& exchange) {
    observer.OnProxyRequest(exchange);
  };
  hooks.on_done = [&observer](const Exchange& exchange) {
    observer.OnProxyDone(exchange);
  };
  hooks.on_client_bytes = [&observer](std::span<const uint8_t> data) {
    observer.OnClientData(data);
  };
  hooks.on_bytes_to_client = [&observer](std::size_t size) {
    observer.OnBytesToClient(size);
  };

  auto transport =
      std::make_unique<StreamTransport<ClientTlsStream>>(std::move(client));
  if (alpn == "h2") {
    auto server = H2ServerConnection::Create(
        std::move(transport), context.pool, std::move(client_info),
        std::move(hooks), context.proxy_settings);
    server->Start();
    co_await server->WaitClosed();
    server->DetachHooks();
  } else {
    auto server = H1ServerConnection::Create(
        std::move(transport), context.pool, std::move(client_info),
        std::move(hooks), context.proxy_settings);
    co_await server->Run();
    server->DetachHooks();
  }
}

}  // namespace

namespace {

class QuicObserverImpl : public QuicObserver {
 public:
  QuicObserverImpl(const GatewayContext& context, const ConnectionInfo& info,
                   const ClientHello& hello, std::string transport,
                   const asio::any_io_executor& executor)
      : observer_(context, info, "quic") {
    GlobalMetrics().connections_quic.Inc();
    observer_.set_executor(executor);
    observer_.OnQuicClientHello(hello, std::move(transport));
    observer_.OnRoute("terminate", "certificate");
    log::Debug("conn={} quic peer={} sni={}", info.id,
               FormatEndpoint(info.peer), hello.server_name);
  }

  ProxyHooks Hooks() override {
    ProxyHooks hooks;
    hooks.on_request = [this](Exchange& exchange) {
      observer_.OnProxyRequest(exchange);
    };
    hooks.on_done = [this](const Exchange& exchange) {
      observer_.OnProxyDone(exchange);
    };
    hooks.on_client_bytes = [this](std::span<const uint8_t> data) {
      observer_.OnClientData(data);
    };
    hooks.on_bytes_to_client = [this](std::size_t size) {
      observer_.OnBytesToClient(size);
    };
    return hooks;
  }

 private:
  ActiveConnection active_;
  ConnectionObserver observer_;
};

}  // namespace

std::unique_ptr<QuicObserver> MakeQuicObserver(
    const GatewayContext& context, const asio::ip::udp::endpoint& peer,
    const asio::ip::udp::endpoint& local, const ClientHello& hello,
    std::string transport_params, const asio::any_io_executor& executor) {
  ConnectionInfo info;
  info.id = NextConnectionId();
  info.peer = tcp::endpoint(peer.address(), peer.port());
  info.local = tcp::endpoint(local.address(), local.port());
  return std::make_unique<QuicObserverImpl>(
      context, info, hello, std::move(transport_params), executor);
}

std::string FormatEndpoint(const tcp::endpoint& endpoint) {
  if (endpoint.address().is_v6()) {
    return std::format("[{}]:{}", endpoint.address().to_string(),
                       endpoint.port());
  }
  return std::format("{}:{}", endpoint.address().to_string(), endpoint.port());
}

asio::awaitable<void> HandleHttpsConnection(tcp::socket socket,
                                            const GatewayContext& context) {
  ActiveConnection active;
  Metrics& metrics = GlobalMetrics();
  metrics.connections_https.Inc();
  const ConnectionInfo info = MakeConnectionInfo(socket);
  PendingSlot pending;
  const std::size_t pending_limit = context.config->pending_connections_per_ip;
  if (pending_limit > 0 &&
      !pending.Acquire(context.pending_counter,
                       Unmapped(info.peer.address()).to_string(),
                       pending_limit)) {
    metrics.rejected_pending_per_ip.Inc();
    co_return;
  }
  ConnectionObserver observer(context, info, "https");
  observer.set_executor(socket.get_executor());
  observer.set_pending_slot(&pending);
  if (const auto syn = ReadSavedSyn(socket.native_handle()); !syn.empty()) {
    metrics.syn_captured.Inc();
    observer.OnSyn(syn);
  }
  SetNoDelay(socket);

  std::vector<uint8_t> buffer;
  buffer.reserve(kHelloReadChunk);
  ClientHello hello;
  ParseStatus status = ParseStatus::kNeedMore;
  {
    auto executor = co_await asio::this_coro::executor;
    ScopedWatchdog deadline(executor, context.config->client_hello_timeout,
                            [&socket] { CloseQuietly(socket); });
    std::array<uint8_t, kHelloReadChunk> chunk;
    while (status == ParseStatus::kNeedMore) {
      auto [ec, n] = co_await socket.async_read_some(asio::buffer(chunk), kUse);
      if (ec) {
        if (deadline->expired()) metrics.client_hello_timeouts.Inc();
        observer.OnRoute("reject", deadline->expired() ? "client_hello_timeout"
                                                       : "closed_before_hello");
        co_return;
      }
      buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
      status = ParseClientHello(buffer, &hello);
    }
  }

  RouteDecision decision = context.classifier->Classify(
      status, hello, *context.certificates->snapshot());
  if (decision.route == Route::kTerminate && context.labels != nullptr &&
      context.labels->snapshot()->IsPassthrough(hello.server_name)) {
    decision = {Route::kPassthrough, RouteReason::kPassthroughPolicy, nullptr};
  }
  CountRoute(decision);
  if (status == ParseStatus::kOk) observer.OnClientHello(hello);
  observer.OnRoute(RouteName(decision.route), RouteReasonName(decision.reason));
  log::Debug("conn={} peer={} sni={} alpn={} route={} reason={}", info.id,
             FormatEndpoint(info.peer),
             hello.server_name.empty() ? "-" : hello.server_name,
             hello.alpn.empty() ? "-" : hello.alpn.front(),
             RouteName(decision.route), RouteReasonName(decision.reason));

  switch (decision.route) {
    case Route::kReject:
      co_return;
    case Route::kPassthrough:
      // Nothing more to see here; Traefik applies its own timeouts.
      observer.set_pending_slot(nullptr);
      pending.Release();
      co_await RunPassthrough(std::move(socket), std::move(buffer),
                              context.upstream_https, info, hello.server_name,
                              context, observer);
      co_return;
    case Route::kTerminate:
      co_await RunTerminate(
          std::move(socket), std::move(buffer), std::move(decision.certificate),
          std::move(hello.server_name), info, context, observer);
      co_return;
  }
}

asio::awaitable<void> HandleHttpConnection(tcp::socket socket,
                                           const GatewayContext& context) {
  ActiveConnection active;
  Metrics& metrics = GlobalMetrics();
  metrics.connections_http.Inc();
  const ConnectionInfo info = MakeConnectionInfo(socket);
  ConnectionObserver observer(context, info, "http");
  if (const auto syn = ReadSavedSyn(socket.native_handle()); !syn.empty()) {
    metrics.syn_captured.Inc();
    observer.OnSyn(syn);
  }
  observer.OnRoute("passthrough", "plain_http");
  // Plain HTTP is readable as is: tap it like a terminated HTTP/1.1 stream.
  observer.StartHttpTap();
  SetNoDelay(socket);
  co_await RunPassthrough(std::move(socket), {}, context.upstream_http, info,
                          "", context, observer);
}

}  // namespace bot_shield
