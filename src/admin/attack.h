#ifndef BOT_SHIELD_ADMIN_ATTACK_H_
#define BOT_SHIELD_ADMIN_ATTACK_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ratelimit/gcra.h"
#include "ratelimit/store.h"

namespace bot_shield {

// One host (or "*.parent", or "*" for every host) under attack.
struct AttackEntry {
  std::string host;
  // "admin" (admin API) or "auto" (attack.auto_rps).
  std::string source;
  int64_t since = 0;  // Unix seconds.
  int64_t until = 0;  // Unix seconds; 0 = until switched off.
};

// Under-attack mode: on these hosts every client without a valid clearance
// token gets the JS challenge, whatever its score and the host's mode.
// Switched by the admin API, or automatically for a host whose request rate
// stays above a threshold. Shared by all workers; Active() skips the lock
// while nothing is under attack (the common case). Kept in memory only.
class AttackMode {
 public:
  static constexpr std::size_t kMaxEntries = 1024;

  // `auto_rps` 0 turns automatic activation off.
  AttackMode(int64_t auto_rps, int64_t auto_duration_seconds);

  AttackMode(const AttackMode&) = delete;
  AttackMode& operator=(const AttackMode&) = delete;

  // `host` is normalized, without a port.
  bool Active(std::string_view host, int64_t now) const;

  // Counts a request to `host` and switches the host on once its rate has
  // been above auto_rps for about ten seconds (a burst of ten seconds'
  // worth). Returns true when this call switched it on.
  bool CountRequest(std::string_view host, int64_t now, int64_t now_ns,
                    RateLimitStore* store);

  // Adds the entry or replaces the one for the same host. False (with
  // `error`) for an invalid host or when the table is full.
  bool Enable(AttackEntry entry, int64_t now, std::string* error);
  bool Disable(std::string_view host);
  // Entries still in effect at `now`.
  std::vector<AttackEntry> Entries(int64_t now) const;

  int64_t auto_rps() const { return auto_rps_; }

  // Called on the worker that switched a host on automatically (once per
  // switch); must not block. Set before traffic starts.
  void set_on_auto(std::function<void(const AttackEntry& entry)> on_auto) {
    on_auto_ = std::move(on_auto);
  }

 private:
  // Drops expired entries; needs `mutex_`.
  void SweepLocked(int64_t now) const;

  const int64_t auto_rps_;
  const int64_t auto_duration_seconds_;
  const GcraParams auto_params_;
  std::function<void(const AttackEntry& entry)> on_auto_;
  mutable std::mutex mutex_;
  mutable std::vector<AttackEntry> entries_;
  mutable std::atomic<std::size_t> count_{0};
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_ATTACK_H_
