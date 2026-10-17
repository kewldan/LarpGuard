#include "common/log.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>

namespace bot_shield::log {
namespace {

std::atomic<Level> g_level{Level::kInfo};

std::string_view LevelName(Level level) {
  switch (level) {
    case Level::kDebug:
      return "DEBUG";
    case Level::kInfo:
      return "INFO";
    case Level::kWarn:
      return "WARN";
    case Level::kError:
      return "ERROR";
  }
  return "?";
}

std::string Timestamp() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch())
                          .count() %
                      1000;
  std::tm tm{};
  gmtime_r(&seconds, &tm);
  char buffer[32];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
  return std::format("{}.{:03}Z", buffer, millis);
}

}  // namespace

void SetLevel(Level level) { g_level.store(level, std::memory_order_relaxed); }

Level CurrentLevel() { return g_level.load(std::memory_order_relaxed); }

bool ParseLevel(std::string_view text, Level* level) {
  if (text == "debug") {
    *level = Level::kDebug;
  } else if (text == "info") {
    *level = Level::kInfo;
  } else if (text == "warn") {
    *level = Level::kWarn;
  } else if (text == "error") {
    *level = Level::kError;
  } else {
    return false;
  }
  return true;
}

void Write(Level level, std::string_view message) {
  const std::string line =
      std::format("{} {:5} {}\n", Timestamp(), LevelName(level), message);
  std::fwrite(line.data(), 1, line.size(), stderr);
}

}  // namespace bot_shield::log
