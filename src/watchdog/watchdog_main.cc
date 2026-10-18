// bot-shield-watchdog: fail-open for bot-shield (docs/architecture.md, 11).
// Polls the gateway's /health and runs a command to send :443/:80 straight
// to Traefik when the gateway fails, and another one when it recovers.

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include "common/log.h"
#include "common/version.h"
#include "config/config.h"
#include "watchdog/fail_open.h"

namespace {

constexpr char kUsage[] =
    R"(Usage: bot-shield-watchdog --on-fail CMD --on-recover CMD [options]

  --health HOST:PORT    gateway metrics listener (default 127.0.0.1:9900)
  --interval DURATION   time between checks (default 1s)
  --timeout DURATION    timeout of one check (default 2s)
  --fail-after N        failed checks in a row before failing open (3)
  --recover-after N     good checks in a row before going back (5)
  --on-fail CMD         shell command that sends traffic to Traefik
  --on-recover CMD      shell command that sends it back to the gateway
  --state-file PATH     Prometheus textfile with the current state
)";

std::atomic<bool> stop{false};

void OnSignal(int /*signal*/) { stop.store(true); }

void WriteState(const std::string& path, bool open, int64_t switches) {
  if (path.empty()) return;
  const std::string temp = path + ".tmp";
  {
    std::ofstream out(temp);
    out << "# HELP bot_shield_failopen_active 1 while traffic bypasses "
           "bot-shield.\n# TYPE bot_shield_failopen_active gauge\n"
        << "bot_shield_failopen_active " << (open ? 1 : 0) << "\n"
        << "# HELP bot_shield_failopen_switches_total Fail-open state "
           "changes.\n# TYPE bot_shield_failopen_switches_total counter\n"
        << "bot_shield_failopen_switches_total " << switches << "\n";
  }
  std::rename(temp.c_str(), path.c_str());
}

// Positive integer, or 0 on bad input.
int ParseCount(const std::string& text) {
  int value = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  return ec == std::errc() && ptr == text.data() + text.size() && value > 0
             ? value
             : 0;
}

bool RunCommand(const std::string& command) {
  // The commands come from the operator's command line (nft scripts).
  // NOLINTNEXTLINE(cert-env33-c,bugprone-command-processor,concurrency-mt-unsafe)
  const int status = std::system(command.c_str());
  return status == 0;
}

int Run(int argc, char** argv) {
  using bot_shield::log::Error;
  using bot_shield::log::Info;
  using bot_shield::log::Warn;

  bot_shield::Endpoint health{"127.0.0.1", 9900};
  std::chrono::milliseconds interval{1000};
  std::chrono::milliseconds timeout{2000};
  int fail_after = 3;
  int recover_after = 5;
  std::string on_fail;
  std::string on_recover;
  std::string state_file;

  for (int i = 1; i < argc; ++i) {
    const std::string_view flag = argv[i];
    if (flag == "--version") {
      std::fputs(
          std::format("bot-shield-watchdog {}\n", bot_shield::kVersion).c_str(),
          stdout);
      return 0;
    }
    if (flag == "--help" || i + 1 >= argc) {
      std::fputs(kUsage, flag == "--help" ? stdout : stderr);
      return flag == "--help" ? 0 : 2;
    }
    const std::string value = argv[++i];
    bool ok = true;
    if (flag == "--health") {
      ok = bot_shield::ParseEndpoint(value, &health);
    } else if (flag == "--interval") {
      ok = bot_shield::ParseDuration(value, &interval);
    } else if (flag == "--timeout") {
      ok = bot_shield::ParseDuration(value, &timeout);
    } else if (flag == "--fail-after") {
      fail_after = ParseCount(value);
      ok = fail_after > 0;
    } else if (flag == "--recover-after") {
      recover_after = ParseCount(value);
      ok = recover_after > 0;
    } else if (flag == "--on-fail") {
      on_fail = value;
    } else if (flag == "--on-recover") {
      on_recover = value;
    } else if (flag == "--state-file") {
      state_file = value;
    } else {
      ok = false;
    }
    if (!ok) {
      Error("bad option {} {}", flag, value);
      return 2;
    }
  }
  if (on_fail.empty() || on_recover.empty()) {
    std::fputs(kUsage, stderr);
    return 2;
  }

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);
  Info(
      "watching http://{}/health every {} ms (fail after {}, recover after "
      "{})",
      health.ToString(), interval.count(), fail_after, recover_after);

  bot_shield::FailOpenSwitch fail_open(fail_after, recover_after);
  int64_t switches = 0;
  std::string last_detail;
  while (!stop.load()) {
    const auto started = std::chrono::steady_clock::now();
    std::string detail;
    const bool healthy = bot_shield::ProbeHealth(health, timeout, &detail);
    if (!healthy && detail != last_detail) {
      Warn("health check failed: {}", detail);
    }
    last_detail = healthy ? "" : detail;
    using Change = bot_shield::FailOpenSwitch::Change;
    const Change change = fail_open.Observe(healthy);
    if (change != Change::kNone) {
      const bool open = change == Change::kOpen;
      if (RunCommand(open ? on_fail : on_recover)) {
        fail_open.Applied(change);
        ++switches;
        if (open) {
          Warn("gateway unhealthy: traffic now goes straight to Traefik");
        } else {
          Info("gateway healthy: traffic goes through bot-shield");
        }
      } else {
        Error("{} command failed; retrying", open ? "on-fail" : "on-recover");
      }
    }
    WriteState(state_file, fail_open.open().value_or(false), switches);
    std::this_thread::sleep_until(started + interval);
  }
  // The redirect stays as it is: availability over protection (ADR-012).
  Info("stopped (fail-open {})",
       fail_open.open().value_or(false) ? "active" : "inactive");
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
