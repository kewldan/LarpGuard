#ifndef BOT_SHIELD_ADMIN_MODES_H_
#define BOT_SHIELD_ADMIN_MODES_H_

#include <cstddef>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "score/policy.h"

namespace bot_shield {

// Host modes set through the admin API (POST /policy, the console). They
// beat policy.hosts and labels and survive restarts in an optional JSON
// file ({"shop.example.com": "enforce", ...}). The gateway applies them by
// rebuilding the verdict set (WithConsoleModes); this store only keeps
// them.
class ModeOverrides {
 public:
  static constexpr std::size_t kMaxEntries = 1000;

  // `file` empty: memory only.
  explicit ModeOverrides(std::string file);

  ModeOverrides(const ModeOverrides&) = delete;
  ModeOverrides& operator=(const ModeOverrides&) = delete;

  // Loads the file (missing file: no overrides).
  bool Load(std::string* error);

  // `host`: an exact name or "*.parent" (normalized). Replaces an existing
  // override of the same host.
  bool Set(std::string_view host, HostMode mode, std::string* error);
  // False with `error` when the host has no override or saving failed.
  bool Remove(std::string_view host, std::string* error);
  std::vector<std::pair<std::string, HostMode>> Entries() const;

 private:
  bool SaveLocked(std::string* error) const;

  const std::string file_;
  mutable std::mutex mutex_;
  std::vector<std::pair<std::string, HostMode>> entries_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_MODES_H_
