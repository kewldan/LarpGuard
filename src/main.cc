#include <openssl/rand.h>
// SIGPIPE/SIGHUP are POSIX, not part of <csignal>: include-cleaner wants
// <signal.h> on Linux and <sys/signal.h> on macOS.
// NOLINTNEXTLINE(modernize-deprecated-headers)
#include <signal.h>      // IWYU pragma: keep
#include <sys/signal.h>  // IWYU pragma: keep

#include <algorithm>
#include <asio/io_context.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/modes.h"
#include "admin/settings.h"
#include "behavior/behavior.h"
#include "challenge/captcha.h"
#include "challenge/challenger.h"
#include "challenge/token.h"
#include "common/compress.h"
#include "common/hash.h"
#include "common/log.h"
#include "common/metrics.h"
#include "common/network.h"
#include "common/refresher.h"
#include "common/systemd.h"
#include "common/version.h"
#include "config/config.h"
#include "config/settings.h"
#include "crawler/ranges.h"
#include "crawler/verifier.h"
#include "crawler/web_bot_auth.h"
#include "docker/labels.h"
#include "docker/watcher.h"
#include "events/events.h"
#include "events/nats_publisher.h"
#include "net/asn.h"
#include "net/geoip.h"
#include "net/http_client.h"
#include "net/threat_lists.h"
#include "notify/notifier.h"
#include "score/policy.h"
#include "server/gateway.h"
#include "server/verdicts.h"
#include "tls/acme_watcher.h"
#include "tls/cert_store.h"
#include "xdp/xdp_filter.h"

namespace {

using bot_shield::kVersion;
#if BOT_SHIELD_FOXIO
constexpr const char* kFeatures = "ja4plus";
#else
constexpr const char* kFeatures = "no-ja4plus";
#endif
constexpr const char* kDefaultConfigPath = "/etc/bot-shield/bot-shield.yaml";

void PrintUsage() {
  std::fputs(
      "Usage: bot-shield [--config PATH] [--check-config] [--version]\n"
      "\n"
      "  --config PATH    configuration file (default "
      "/etc/bot-shield/bot-shield.yaml)\n"
      "  --check-config   validate the configuration and exit\n"
      "  --version        print the version and exit\n",
      stdout);
}

struct Options {
  std::string config_path = kDefaultConfigPath;
  bool check_config = false;
};

// Returns -1 to continue, otherwise the process exit code.
int ParseArgs(int argc, char** argv, Options* options) {
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--config" && i + 1 < argc) {
      options->config_path = argv[++i];
    } else if (arg == "--check-config") {
      options->check_config = true;
    } else if (arg == "--version") {
      std::printf("bot-shield %.*s (%s)\n", static_cast<int>(kVersion.size()),
                  kVersion.data(), kFeatures);
      return 0;
    } else if (arg == "-h" || arg == "--help") {
      PrintUsage();
      return 0;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argv[i]);
      PrintUsage();
      return 2;
    }
  }
  return -1;
}

std::string RandomHex(std::size_t bytes) {
  std::string raw(bytes, '\0');
  RAND_bytes(reinterpret_cast<uint8_t*>(raw.data()), raw.size());
  return bot_shield::HexEncode(raw);
}

// One line about the verdict set for the log and POST /reload.
std::string VerdictSummary(const bot_shield::VerdictSet& set,
                           const bot_shield::Config& config) {
  return std::format(
      "generation {}, library {} ({} browser profiles, {} automation), "
      "mode {}, model {}",
      set.generation, set.library->version(), set.library->profile_count(),
      set.library->automation().size(),
      config.policy.enforce ? "enforce" : "shadow",
      set.model ? std::format("{} trees", set.model->tree_count()) : "off");
}

// What XDP drops: global IP/CIDR block entries of the admin lists (unless
// an allow entry covers them: allow wins) and the gateway's own blocks.
bot_shield::XdpBlocklist XdpBlocklistFrom(
    const std::vector<bot_shield::ListEntry>& entries,
    bot_shield::XdpBlocklist automatic) {
  std::vector<bot_shield::Network> allowed;
  for (const bot_shield::ListEntry& entry : entries) {
    if (entry.kind == bot_shield::ListKind::kIp && entry.host.empty() &&
        entry.action == bot_shield::Action::kAllow) {
      allowed.push_back(entry.network);
    }
  }
  const auto is_allowed = [&allowed](const bot_shield::Network& network) {
    return std::ranges::any_of(
        allowed, [&network](const bot_shield::Network& allow) {
          return allow.prefix <= network.prefix &&
                 allow.Contains(asio::ip::address_v6(network.bytes));
        });
  };
  bot_shield::XdpBlocklist out;
  for (const bot_shield::ListEntry& entry : entries) {
    if (entry.kind == bot_shield::ListKind::kIp && entry.host.empty() &&
        entry.action == bot_shield::Action::kBlock &&
        !is_allowed(entry.network)) {
      out.emplace_back(entry.network, entry.expires_at);
    }
  }
  for (auto& item : automatic) {
    if (!is_allowed(item.first)) out.push_back(std::move(item));
  }
  return out;
}

int Run(int argc, char** argv) {
  using bot_shield::log::Error;
  using bot_shield::log::Info;

  Options options;
  if (const int code = ParseArgs(argc, argv, &options); code >= 0) return code;

  // The main file plus the console's settings layer (ADR-018).
  bot_shield::SettingsLayer settings(options.config_path);
  bot_shield::Config config;
  std::string error;
  if (!settings.Load(&config, options.check_config, &error)) {
    Error("config: {}", error);
    return 1;
  }
  if (options.check_config) {
    std::printf("%s: OK\n", options.config_path.c_str());
    return 0;
  }
  bot_shield::log::SetLevel(config.log_level);
  std::signal(SIGPIPE, SIG_IGN);
  Info("bot-shield {} starting", kVersion);
  if (!settings.load_error().empty()) {
    Error("settings layer rejected: {}", settings.load_error());
  } else if (!settings.layer().empty()) {
    Info("settings: console layer {} over {}", settings.revision(),
         options.config_path);
  }

  bot_shield::CertStore certificates;
  bot_shield::AcmeWatcher watcher(config.acme_json, config.acme_reload_interval,
                                  &certificates);
  if (!watcher.LoadNow()) {
    bot_shield::log::Warn(
        "no certificates loaded yet; all TLS traffic is passed through to "
        "Traefik until {} becomes readable",
        config.acme_json);
  }
  watcher.Start();

  bot_shield::EventSettings event_settings;
  event_settings.instance = RandomHex(8);
  event_settings.ip_salt =
      config.events_ip_salt.empty() ? RandomHex(32) : config.events_ip_salt;
  event_settings.requests = config.events_requests;
  std::unique_ptr<bot_shield::NatsPublisher> publisher;
  if (config.events_nats) {
    bot_shield::NatsSettings nats;
    if (!bot_shield::ResolveEndpoint(*config.events_nats, &nats.server,
                                     &error)) {
      Error("events: {}", error);
      return 1;
    }
    nats.subject_prefix = config.events_subject_prefix;
    nats.token = config.events_token;
    nats.user = config.events_user;
    nats.password = config.events_password;
    nats.max_queue = config.events_max_queue;
    publisher = std::make_unique<bot_shield::NatsPublisher>(std::move(nats));
    publisher->Start();
    Info("events: publishing to {} as {}.*", config.events_nats->ToString(),
         config.events_subject_prefix);
  }

  // Operator notifications ("notify"); a no-op without a destination. The
  // NATS watch outlives the notifier, whose thread samples it.
  std::optional<bot_shield::NatsWatch> nats_watch;
  bot_shield::OperatorNotifier notifier(bot_shield::NotifySettingsFrom(config));
  if (config.events_nats) {
    nats_watch.emplace(config.events_nats->ToString(),
                       config.notify_nats_down_after);
    notifier.Every(std::chrono::seconds(5), [&nats_watch, &notifier] {
      const auto& metrics = bot_shield::GlobalMetrics();
      if (auto message = nats_watch->Observe(
              metrics.nats_connected.Get() == 1,
              static_cast<int64_t>(metrics.events_dropped.Get()),
              std::chrono::steady_clock::now())) {
        notifier.Send(std::move(*message));
      }
    });
  }
  notifier.Start();
  if (!config.notify_webhook.empty() || !config.notify_telegram_token.empty()) {
    const bool both =
        !config.notify_webhook.empty() && !config.notify_telegram_token.empty();
    Info("notify: {}", both                            ? "webhook and telegram"
                       : config.notify_webhook.empty() ? "telegram"
                                                       : "webhook");
  }

  // Host modes set from the console (POST /policy); applied on top of
  // every verdict set.
  bot_shield::ModeOverrides modes(config.admin_modes_file);
  if (!modes.Load(&error)) {
    Error("admin: {}", error);
    return 1;
  }

  // Library, policy, rules, limits and model; replaced by SIGHUP and
  // POST /reload without a restart.
  bot_shield::VerdictStore verdicts;
  {
    std::shared_ptr<const bot_shield::VerdictSet> initial;
    if (!bot_shield::VerdictSet::Build(config, &initial, &error)) {
      Error("{}", error);
      return 1;
    }
    verdicts.set(bot_shield::WithConsoleModes(*initial, modes.Entries()));
  }
  Info("{}", VerdictSummary(*verdicts.snapshot(), config));
  std::mutex reload_mutex;
  // Re-reads the file; only the verdict sections take effect (the rest
  // needs a restart). Nothing changes when the new file is invalid.
  const auto reload = [&](std::string* summary) {
    const std::scoped_lock lock(reload_mutex);
    bot_shield::Config fresh;
    std::shared_ptr<const bot_shield::VerdictSet> next;
    if (!settings.Reload(&fresh, summary) ||
        !bot_shield::VerdictSet::Build(fresh, &next, summary)) {
      Error("reload failed, keeping the current configuration: {}", *summary);
      notifier.Send({"reload_failed", "",
                     std::format("reload rejected, the current configuration "
                                 "stays: {}",
                                 *summary)});
      return false;
    }
    verdicts.set(bot_shield::WithConsoleModes(*next, modes.Entries()));
    *summary = VerdictSummary(*verdicts.snapshot(), fresh);
    Info("reloaded: {}", *summary);
    return true;
  };
  // Applies a console settings change: the verdict set is built first, the
  // layer written next, and the set published only when both worked.
  const auto apply_settings = [&](const bot_shield::Config& next_config,
                                  const std::function<bool()>& commit,
                                  std::string* apply_error) {
    const std::scoped_lock lock(reload_mutex);
    std::shared_ptr<const bot_shield::VerdictSet> next;
    if (!bot_shield::VerdictSet::Build(next_config, &next, apply_error) ||
        !commit()) {
      return false;
    }
    verdicts.set(bot_shield::WithConsoleModes(*next, modes.Entries()));
    Info("settings applied: {}",
         VerdictSummary(*verdicts.snapshot(), next_config));
    return true;
  };
  // Applies changed console modes; serialized with reloads so neither
  // publishes a set built from the other's stale snapshot.
  const auto publish_modes = [&] {
    const std::scoped_lock lock(reload_mutex);
    verdicts.set(
        bot_shield::WithConsoleModes(*verdicts.snapshot(), modes.Entries()));
  };

  bot_shield::LabelStore labels;
  std::unique_ptr<bot_shield::DockerWatcher> docker;
  if (!config.docker_socket.empty()) {
    docker = std::make_unique<bot_shield::DockerWatcher>(
        config.docker_socket, config.docker_poll_interval, &labels);
    docker->PollNow();
    docker->Start();
  }

  bot_shield::ListStore lists(config.admin_state_file);
  if (!lists.Load(std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count(),
                  &error)) {
    Error("admin: {}", error);
    return 1;
  }
  bot_shield::DecisionLog decisions(config.admin_decisions);

  bot_shield::ChallengeSettings challenge;
  if (config.challenge_keys_file.empty()) {
    challenge.keys = bot_shield::TokenKeys::Random();
    bot_shield::log::Warn(
        "challenge: no keys_file, using a random key (clearance tokens are "
        "lost on restart)");
  } else if (!bot_shield::TokenKeys::Load(config.challenge_keys_file,
                                          &challenge.keys, &error)) {
    Error("challenge: {}", error);
    return 1;
  }
  challenge.token_ttl = std::chrono::duration_cast<std::chrono::seconds>(
      config.challenge_token_ttl);
  challenge.suspicious_difficulty = config.challenge_suspicious_difficulty;
  challenge.bot_difficulty = config.challenge_bot_difficulty;
  challenge.token_credit = config.challenge_token_credit;
  const bot_shield::Challenger challenger(std::move(challenge));

  std::optional<bot_shield::CrawlerVerifier> crawler_verifier;
  if (config.crawlers_verify) {
    crawler_verifier.emplace(bot_shield::CrawlerVerifier::SystemResolver(),
                             bot_shield::CrawlerVerifier::Settings());
  }

  // Outbound downloads: published crawler ranges and the ASN database,
  // refreshed in the background and cached in data_dir.
  if (!config.ca_file.empty()) bot_shield::SetHttpClientCaFile(config.ca_file);
  if (!config.data_dir.empty()) {
    std::error_code dir_error;
    std::filesystem::create_directories(config.data_dir, dir_error);
    if (dir_error) {
      bot_shield::log::Warn("data_dir {}: {}", config.data_dir,
                            dir_error.message());
    }
  }
  bot_shield::CrawlerRangeStore crawler_ranges;
  bot_shield::AsnStore asn;
  std::vector<bot_shield::RefreshSource> sources;
  if (config.crawlers_ip_ranges) {
    for (bot_shield::RefreshSource& source : bot_shield::CrawlerRangeSources(
             &crawler_ranges, config.data_dir,
             std::chrono::duration_cast<std::chrono::seconds>(
                 config.crawlers_ranges_refresh))) {
      source.apply = [apply = std::move(source.apply), &crawler_ranges](
                         std::string_view data, std::string* apply_error) {
        if (!apply(data, apply_error)) return false;
        bot_shield::GlobalMetrics().crawler_range_sets.Set(
            static_cast<int64_t>(crawler_ranges.snapshot()->size()));
        return true;
      };
      sources.push_back(std::move(source));
    }
  }
  if (!config.asn_url.empty()) {
    bot_shield::RefreshSource source;
    source.name = "asn";
    source.url = config.asn_url;
    if (!config.data_dir.empty()) {
      source.cache_file = config.data_dir + "/ip2asn-combined.tsv.gz";
    }
    source.refresh =
        std::chrono::duration_cast<std::chrono::seconds>(config.asn_refresh);
    source.apply = [&asn](std::string_view data, std::string* apply_error) {
      std::string text;
      // gzip (iptoasn.com) or plain TSV.
      if (data.starts_with("\x1f\x8b")) {
        if (!bot_shield::Gunzip(data, std::size_t{512} << 20, &text,
                                apply_error)) {
          return false;
        }
        data = text;
      }
      auto database = std::make_shared<bot_shield::AsnDatabase>();
      if (!bot_shield::AsnDatabase::Parse(data, database.get(), apply_error)) {
        return false;
      }
      bot_shield::GlobalMetrics().asn_ranges.Set(
          static_cast<int64_t>(database->size()));
      asn.set(std::move(database));
      return true;
    };
    sources.push_back(std::move(source));
  }
  bot_shield::GeoStore geoip;
  if (!config.geoip_url.empty()) {
    bot_shield::RefreshSource source;
    source.name = "geoip";
    source.url = config.geoip_url;
    if (!config.data_dir.empty()) {
      source.cache_file = config.data_dir + "/geoip-country.csv.gz";
    }
    source.refresh =
        std::chrono::duration_cast<std::chrono::seconds>(config.geoip_refresh);
    source.max_size = std::size_t{64} << 20;
    // This month's file, or last month's until the new one is out.
    source.fetch = [](const std::string& url, std::size_t max_size,
                      const std::stop_token& stop, std::string* data,
                      std::string* fetch_error) {
      int year = 0;
      int month = 0;
      bot_shield::YearMonthOfUnixDay(
          std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
                  .count() /
              86400,
          &year, &month);
      for (const std::string& month_url :
           bot_shield::GeoUrlsToTry(url, year, month)) {
        if (bot_shield::FetchUrl(month_url, max_size, stop, data,
                                 fetch_error)) {
          return true;
        }
      }
      return false;
    };
    source.apply = [&geoip](std::string_view data, std::string* apply_error) {
      std::string text;
      if (data.starts_with("\x1f\x8b")) {
        if (!bot_shield::Gunzip(data, std::size_t{512} << 20, &text,
                                apply_error)) {
          return false;
        }
        data = text;
      }
      auto database = std::make_shared<bot_shield::GeoDatabase>();
      if (!bot_shield::GeoDatabase::Parse(data, database.get(), apply_error)) {
        return false;
      }
      geoip.set(std::move(database));
      return true;
    };
    sources.push_back(std::move(source));
  }
  bot_shield::ThreatListStore threat_lists;
  for (bot_shield::RefreshSource& source : bot_shield::ThreatListSources(
           config.threat_lists, &threat_lists, config.data_dir,
           std::chrono::duration_cast<std::chrono::seconds>(
               config.threat_lists_refresh))) {
    sources.push_back(std::move(source));
  }
  bot_shield::DataRefresher refresher(std::move(sources));
  refresher.Start();

  std::optional<bot_shield::WebBotAuthVerifier> web_bot_auth;
  if (config.web_bot_auth_enabled) {
    bot_shield::WebBotAuthVerifier::Settings settings;
    settings.limits.max_validity_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(
            config.web_bot_auth_max_validity)
            .count();
    web_bot_auth.emplace(settings);
  }

  std::unique_ptr<bot_shield::Captcha> captcha;
  bot_shield::CaptchaProvider provider = bot_shield::CaptchaProvider::kNone;
  bot_shield::ParseCaptchaProvider(config.captcha_provider, &provider);
  if (provider != bot_shield::CaptchaProvider::kNone) {
    bot_shield::CaptchaSettings settings;
    settings.provider = provider;
    settings.site_key = config.captcha_site_key;
    settings.verify_url = config.captcha_verify_url;
    settings.check_hostname = config.captcha_check_hostname;
    settings.rounds = config.captcha_rounds;
    settings.round_timeout = std::chrono::duration_cast<std::chrono::seconds>(
        config.captcha_round_timeout);
    settings.difficulty = config.captcha_difficulty;
    settings.secret = config.captcha_secret;
    if (!config.captcha_secret_file.empty()) {
      std::ifstream secret_file(config.captcha_secret_file);
      if (!secret_file || !std::getline(secret_file, settings.secret) ||
          settings.secret.empty()) {
        Error("captcha: cannot read secret_file {}",
              config.captcha_secret_file);
        return 1;
      }
      while (!settings.secret.empty() && (settings.secret.back() == '\r' ||
                                          settings.secret.back() == ' ')) {
        settings.secret.pop_back();
      }
    }
    captcha =
        std::make_unique<bot_shield::Captcha>(std::move(settings), &challenger);
  }
  bot_shield::XdpAutoBlocks xdp_blocks;

  bot_shield::GatewayServices services;
  services.challenger = &challenger;
  services.captcha = captcha.get();
  services.crawler_ranges =
      config.crawlers_ip_ranges ? &crawler_ranges : nullptr;
  if (web_bot_auth) services.web_bot_auth = &*web_bot_auth;
  services.asn = config.asn_url.empty() ? nullptr : &asn;
  services.threat_lists = config.threat_lists.empty() ? nullptr : &threat_lists;
  services.geoip = config.geoip_url.empty() ? nullptr : &geoip;
  services.xdp_blocks =
      config.xdp_enabled && config.xdp_block_honeypot ? &xdp_blocks : nullptr;
  if (crawler_verifier) services.crawler_verifier = &*crawler_verifier;
  std::optional<bot_shield::BehaviorStore> behavior;
  if (config.behavior_enabled) {
    bot_shield::BehaviorSettings settings;
    settings.window = std::chrono::duration_cast<std::chrono::seconds>(
        config.behavior_window);
    settings.max_clients = config.behavior_max_clients;
    behavior.emplace(settings);
    services.behavior = &*behavior;
  }
  services.events = publisher.get();
  services.event_settings = &event_settings;
  services.verdicts = &verdicts;
  services.reload = reload;
  services.on_attack_auto = [&notifier,
                             &config](const bot_shield::AttackEntry& entry) {
    const std::string who =
        entry.kind.empty() ? entry.host
                           : std::format("{} {} on {}",
                                         entry.kind == "ip_prefix" ? "network"
                                         : entry.kind == "asn"     ? "AS"
                                                                   : "JA4",
                                         entry.value, entry.host);
    notifier.Send(
        {"attack_auto", entry.host,
         std::format("under-attack mode on for {} for {}: over {} requests/s",
                     who,
                     bot_shield::FormatDuration(
                         std::chrono::seconds(entry.until - entry.since)),
                     config.attack_auto_rps)});
  };
  services.modes = &modes;
  services.publish_modes = publish_modes;
  services.settings = &settings;
  services.apply_settings = apply_settings;
  services.labels = docker ? &labels : nullptr;
  services.lists = &lists;
  services.decisions = &decisions;
  bot_shield::Gateway gateway(config, &certificates, services);
  if (!gateway.Start(&error)) {
    Error("startup: {}", error);
    return 1;
  }

  // XDP pre-filter: blocklists from the admin lists (IP/CIDR, all hosts)
  // and honeypot hits. A failure leaves the gateway running without it.
  std::unique_ptr<bot_shield::XdpFilter> xdp;
  if (config.xdp_enabled) {
    bot_shield::XdpSettings settings;
    settings.interface = config.xdp_interface;
    settings.mode = config.xdp_mode;
    settings.ports = {config.listen_https.port};
    if (config.listen_http) settings.ports.push_back(config.listen_http->port);
    settings.allow_udp = config.http3_enabled;
    settings.syn_rate = config.xdp_syn_rate;
    settings.syn_burst = config.xdp_syn_burst;
    settings.drop_invalid = config.xdp_drop_invalid;
    settings.drop_fragments = config.xdp_drop_fragments;
    settings.heartbeat_timeout =
        std::chrono::duration_cast<std::chrono::seconds>(
            config.xdp_heartbeat_timeout);
    xdp = bot_shield::XdpFilter::Start(
        settings, [&gateway] { return gateway.Healthy(); },
        [&lists, &xdp_blocks] {
          const int64_t now =
              std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
          return XdpBlocklistFrom(lists.Entries(now), xdp_blocks.Snapshot(now));
        },
        &error);
    if (xdp) {
      bot_shield::GlobalMetrics().xdp_attached.Set(1);
      Info("xdp: attached to {} ({})", config.xdp_interface, xdp->mode());
    } else {
      Error("{} (continuing without XDP)", error);
    }
  }

  // Graceful shutdown: the first signal stops accepting and waits for open
  // connections up to the drain timeout; a second signal stops immediately.
  asio::io_context control;

  // systemd: Type=notify readiness, and WatchdogSec= pings only while every
  // worker loop beats, so systemd restarts a stuck gateway.
  const std::optional<bot_shield::SystemdNotifier> systemd =
      bot_shield::SystemdNotifier::FromEnvironment();
  if (systemd) systemd->Notify("READY=1");
  asio::steady_timer watchdog_timer(control);
  std::function<void()> ping_watchdog;
  if (const auto interval = bot_shield::SystemdNotifier::WatchdogInterval();
      systemd && interval) {
    ping_watchdog = [&, interval = *interval] {
      if (gateway.Healthy()) {
        systemd->Notify("WATCHDOG=1");
      } else {
        bot_shield::log::Warn("worker stalled, not pinging systemd watchdog");
      }
      watchdog_timer.expires_after(interval);
      watchdog_timer.async_wait([&](const std::error_code& ec) {
        if (!ec) ping_watchdog();
      });
    };
    ping_watchdog();
  }
  asio::signal_set signals(control, SIGINT, SIGTERM);
  asio::steady_timer drain_timer(control);
  bool draining = false;
  std::chrono::steady_clock::time_point drain_deadline;

  std::function<void()> poll_drain = [&] {
    const bool deadline_passed =
        std::chrono::steady_clock::now() >= drain_deadline;
    if (gateway.finished() || deadline_passed) {
      if (deadline_passed) {
        Info("drain timeout, closing {} connections",
             bot_shield::GlobalMetrics().connections_active.Get());
      }
      gateway.Stop();
      control.stop();
      return;
    }
    drain_timer.expires_after(std::chrono::milliseconds(100));
    drain_timer.async_wait([&](const std::error_code& ec) {
      if (!ec) poll_drain();
    });
  };

  std::function<void(const std::error_code&, int)> on_signal =
      [&](const std::error_code& ec, int signal_number) {
        if (ec) return;
        if (draining) {
          Info("second signal, stopping now");
          gateway.Stop();
          control.stop();
          return;
        }
        draining = true;
        if (systemd) systemd->Notify("STOPPING=1");
        Info("signal {}, draining {} connections (up to {} ms)", signal_number,
             bot_shield::GlobalMetrics().connections_active.Get(),
             config.drain_timeout.count());
        gateway.StopAccepting();
        drain_deadline =
            std::chrono::steady_clock::now() + config.drain_timeout;
        poll_drain();
        signals.async_wait(on_signal);
      };
  signals.async_wait(on_signal);

  asio::signal_set hangup(control, SIGHUP);
  std::function<void(const std::error_code&, int)> on_hangup =
      [&](const std::error_code& ec, int /*signal*/) {
        if (ec) return;
        std::string summary;
        reload(&summary);
        hangup.async_wait(on_hangup);
      };
  hangup.async_wait(on_hangup);

  control.run();
  xdp.reset();  // Detaches before the workers go.
  gateway.Join();
  if (publisher) publisher->Stop();
  notifier.Stop();
  if (docker) docker->Stop();
  watcher.Stop();
  Info("stopped");
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return Run(argc, argv);
  } catch (const std::exception& e) {
    // Plain stdio: nothing in a handler of last resort may throw again.
    std::fprintf(stderr, "fatal: %s\n", e.what());
  } catch (...) {
    std::fputs("fatal: unknown exception\n", stderr);
  }
  return 1;
}
