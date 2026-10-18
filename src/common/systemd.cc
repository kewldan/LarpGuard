#include "common/systemd.h"

#include <sys/socket.h>
#include <sys/types.h>  // IWYU pragma: keep (ssize_t on Linux)
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace bot_shield {
namespace {

std::optional<int64_t> EnvInt(const char* name) {
  const char* value = std::getenv(name);  // NOLINT(concurrency-mt-unsafe)
  if (value == nullptr) return std::nullopt;
  const std::string_view text(value);
  int64_t out = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), out);
  if (ec != std::errc() || ptr != text.data() + text.size()) {
    return std::nullopt;
  }
  return out;
}

}  // namespace

std::optional<SystemdNotifier> SystemdNotifier::FromEnvironment() {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): read once at startup.
  const char* path = std::getenv("NOTIFY_SOCKET");
  if (path == nullptr || path[0] == '\0') return std::nullopt;
  return SystemdNotifier(path);
}

bool SystemdNotifier::Notify(std::string_view state) const {
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  if (socket_path_.size() >= sizeof(address.sun_path)) return false;
  std::memcpy(address.sun_path, socket_path_.data(), socket_path_.size());
  // Abstract namespace: '@' stands for a leading NUL byte.
  if (address.sun_path[0] == '@') address.sun_path[0] = '\0';
  const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0) return false;
  const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) +
                                             socket_path_.size());
  const ssize_t sent =
      sendto(fd, state.data(), state.size(), 0,
             reinterpret_cast<const sockaddr*>(&address), length);
  close(fd);
  return std::cmp_equal(sent, state.size());
}

std::optional<std::chrono::milliseconds> SystemdNotifier::WatchdogInterval() {
  const std::optional<int64_t> usec = EnvInt("WATCHDOG_USEC");
  if (!usec || *usec <= 0) return std::nullopt;
  if (const std::optional<int64_t> pid = EnvInt("WATCHDOG_PID");
      pid && *pid != getpid()) {
    return std::nullopt;
  }
  return std::chrono::milliseconds(std::max<int64_t>(*usec / 2000, 100));
}

}  // namespace bot_shield
