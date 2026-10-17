#ifndef BOT_SHIELD_COMMON_LOG_H_
#define BOT_SHIELD_COMMON_LOG_H_

#include <format>
#include <string_view>
#include <utility>

namespace bot_shield::log {

enum class Level { kDebug = 0, kInfo = 1, kWarn = 2, kError = 3 };

void SetLevel(Level level);
Level CurrentLevel();

// Parses "debug", "info", "warn" or "error".
bool ParseLevel(std::string_view text, Level* level);

// Writes one line to stderr. A single write per line keeps lines from
// different worker threads from interleaving.
void Write(Level level, std::string_view message);

template <typename... Args>
void Debug(std::format_string<Args...> format, Args&&... args) {
  if (CurrentLevel() <= Level::kDebug) {
    Write(Level::kDebug, std::format(format, std::forward<Args>(args)...));
  }
}

template <typename... Args>
void Info(std::format_string<Args...> format, Args&&... args) {
  if (CurrentLevel() <= Level::kInfo) {
    Write(Level::kInfo, std::format(format, std::forward<Args>(args)...));
  }
}

template <typename... Args>
void Warn(std::format_string<Args...> format, Args&&... args) {
  if (CurrentLevel() <= Level::kWarn) {
    Write(Level::kWarn, std::format(format, std::forward<Args>(args)...));
  }
}

template <typename... Args>
void Error(std::format_string<Args...> format, Args&&... args) {
  Write(Level::kError, std::format(format, std::forward<Args>(args)...));
}

}  // namespace bot_shield::log

#endif  // BOT_SHIELD_COMMON_LOG_H_
