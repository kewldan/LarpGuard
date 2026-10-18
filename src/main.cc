#include <openssl/rand.h>
#include <sys/signal.h>

#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "admin/decision_log.h"
#include "admin/lists.h"
#include "challenge/challenger.h"
#include "challenge/token.h"
#include "common/hash.h"
#include "common/log.h"
#include "common/metrics.h"
#include "common/version.h"
#include "config/config.h"
#include "docker/labels.h"
#include "docker/watcher.h"
#include "events/events.h"
#include "events/nats_publisher.h"
#include "fp/library.h"
#include "server/gateway.h"
#include "tls/acme_watcher.h"
#include "tls/cert_store.h"

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

int Run(int argc, char** argv) {
  using bot_shield::log::Error;
  using bot_shield::log::Info;

  Options options;
  if (const int code = ParseArgs(argc, argv, &options); code >= 0) return code;

  bot_shield::Config config;
  std::string error;
  if (!bot_shield::LoadConfigFile(options.config_path, &config, &error)) {
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

  bot_shield::FingerprintLibrary library =
      bot_shield::FingerprintLibrary::BuiltIn();
  if (!config.fingerprint_library.empty() &&
      !bot_shield::FingerprintLibrary::Load(config.fingerprint_library,
                                            &library, &error)) {
    Error("fingerprints: {}", error);
    return 1;
  }
  Info(
      "fingerprints: library {} ({} browser profiles, {} automation), "
      "mode {}",
      library.version(), library.profile_count(), library.automation().size(),
      config.policy.enforce ? "enforce" : "shadow");

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

  bot_shield::GatewayServices services;
  services.challenger = &challenger;
  services.events = publisher.get();
  services.event_settings = &event_settings;
  services.library = &library;
  services.labels = docker ? &labels : nullptr;
  services.lists = &lists;
  services.decisions = &decisions;
  bot_shield::Gateway gateway(config, &certificates, services);
  if (!gateway.Start(&error)) {
    Error("startup: {}", error);
    return 1;
  }

  // Graceful shutdown: the first signal stops accepting and waits for open
  // connections up to the drain timeout; a second signal stops immediately.
  asio::io_context control;
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

  control.run();
  gateway.Join();
  if (publisher) publisher->Stop();
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
