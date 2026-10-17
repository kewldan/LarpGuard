#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <functional>
#include <string>
#include <string_view>

#include "common/log.h"
#include "common/metrics.h"
#include "config/config.h"
#include "server/gateway.h"
#include "tls/acme_watcher.h"
#include "tls/cert_store.h"

namespace {

constexpr std::string_view kVersion = "0.1.0";
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
      std::printf("bot-shield %.*s\n", static_cast<int>(kVersion.size()),
                  kVersion.data());
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

}  // namespace

int main(int argc, char** argv) {
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

  bot_shield::Gateway gateway(config, &certificates);
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
  watcher.Stop();
  Info("stopped");
  return 0;
}
