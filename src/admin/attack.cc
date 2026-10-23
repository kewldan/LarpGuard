#include "admin/attack.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <format>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/host.h"
#include "common/log.h"
#include "common/metrics.h"
#include "ratelimit/gcra.h"
#include "ratelimit/store.h"

namespace bot_shield {
namespace {

constexpr int64_t kNanosPerSecond = 1'000'000'000;
// Seconds above the threshold before a host is switched on.
constexpr int64_t kAutoWindowSeconds = 10;

bool Matches(const AttackEntry& entry, std::string_view host, int64_t now) {
  if (entry.until != 0 && entry.until <= now) return false;
  return entry.host == "*" || HostMatches(entry.host, host);
}

}  // namespace

AttackMode::AttackMode(int64_t auto_rps, int64_t auto_duration_seconds)
    : auto_rps_(auto_rps),
      auto_duration_seconds_(auto_duration_seconds),
      auto_params_(auto_rps > 0
                       ? GcraParams::FromRate(auto_rps, kNanosPerSecond,
                                              auto_rps * kAutoWindowSeconds)
                       : GcraParams{}) {}

bool AttackMode::Active(std::string_view host, int64_t now) const {
  if (count_.load(std::memory_order_relaxed) == 0) return false;
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  return std::ranges::any_of(entries_, [host, now](const AttackEntry& entry) {
    return Matches(entry, host, now);
  });
}

bool AttackMode::CountRequest(std::string_view host, int64_t now,
                              int64_t now_ns, RateLimitStore* store) {
  if (auto_rps_ <= 0 || host.empty()) return false;
  if (store->Check(std::format("attack\x1f{}", host), auto_params_, now_ns)
          .allowed) {
    return false;
  }
  if (Active(host, now)) return false;
  AttackEntry entry;
  entry.host = std::string(host);
  entry.source = "auto";
  entry.since = now;
  entry.until = now + auto_duration_seconds_;
  std::string error;
  const AttackEntry enabled = entry;
  if (!Enable(std::move(entry), now, &error)) return false;
  GlobalMetrics().attack_auto_activations.Inc();
  log::Warn("under-attack mode on for {} for {}s: over {} requests/s", host,
            auto_duration_seconds_, auto_rps_);
  if (on_auto_) on_auto_(enabled);
  return true;
}

bool AttackMode::Enable(AttackEntry entry, int64_t now, std::string* error) {
  entry.host = NormalizeHost(entry.host);
  const std::string_view name = entry.host.starts_with("*.")
                                    ? std::string_view(entry.host).substr(2)
                                    : std::string_view(entry.host);
  if (entry.host != "*" && !IsValidHostName(name)) {
    *error = std::format("invalid host '{}'", entry.host);
    return false;
  }
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  const auto it = std::ranges::find(entries_, entry.host, &AttackEntry::host);
  if (it != entries_.end()) {
    *it = std::move(entry);
  } else if (entries_.size() >= kMaxEntries) {
    *error = "too many hosts under attack";
    return false;
  } else {
    entries_.push_back(std::move(entry));
  }
  count_.store(entries_.size(), std::memory_order_relaxed);
  GlobalMetrics().attack_hosts.Set(static_cast<int64_t>(entries_.size()));
  return true;
}

bool AttackMode::Disable(std::string_view host) {
  const std::string normalized = NormalizeHost(host);
  const std::scoped_lock lock(mutex_);
  const std::size_t removed = std::erase_if(
      entries_,
      [&normalized](const AttackEntry& e) { return e.host == normalized; });
  count_.store(entries_.size(), std::memory_order_relaxed);
  GlobalMetrics().attack_hosts.Set(static_cast<int64_t>(entries_.size()));
  return removed > 0;
}

std::vector<AttackEntry> AttackMode::Entries(int64_t now) const {
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  return entries_;
}

void AttackMode::SweepLocked(int64_t now) const {
  const std::size_t removed = std::erase_if(entries_, [now](const auto& e) {
    return e.until != 0 && e.until <= now;
  });
  if (removed == 0) return;
  count_.store(entries_.size(), std::memory_order_relaxed);
  GlobalMetrics().attack_hosts.Set(static_cast<int64_t>(entries_.size()));
}

}  // namespace bot_shield
