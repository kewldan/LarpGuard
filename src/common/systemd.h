#ifndef BOT_SHIELD_COMMON_SYSTEMD_H_
#define BOT_SHIELD_COMMON_SYSTEMD_H_

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace bot_shield {

// sd_notify(3) without libsystemd: datagrams to $NOTIFY_SOCKET. Used for
// Type=notify (READY=1, STOPPING=1) and WatchdogSec= (WATCHDOG=1).
class SystemdNotifier {
 public:
  // From the environment; nullopt when not started by systemd with a
  // notify socket.
  static std::optional<SystemdNotifier> FromEnvironment();
  explicit SystemdNotifier(std::string socket_path)
      : socket_path_(std::move(socket_path)) {}

  bool Notify(std::string_view state) const;

  // Half of WatchdogSec (how often to send WATCHDOG=1), or nullopt when
  // the watchdog is off or meant for another process.
  static std::optional<std::chrono::milliseconds> WatchdogInterval();

 private:
  std::string socket_path_;  // "@name" for the abstract namespace.
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_SYSTEMD_H_
