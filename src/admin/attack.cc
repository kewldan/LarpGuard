#include "admin/attack.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
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

// Samples taken per host before a trip, and the share one signature needs.
constexpr std::size_t kSampleRing = 256;
constexpr uint32_t kSampleEvery = 4;
constexpr std::size_t kMinSamples = 32;
constexpr double kDominantShare = 0.5;
// Hosts with samples per shard; beyond, the shard starts over.
constexpr std::size_t kSampledHostsPerShard = 256;
// Signature entries per host; one more trip covers the whole host.
constexpr std::size_t kMaxSignaturesPerHost = 8;

bool Matches(const AttackEntry& entry, const AttackSubject& subject,
             int64_t now) {
  if (entry.until != 0 && entry.until <= now) return false;
  if (entry.host != "*" && !HostMatches(entry.host, subject.host)) {
    return false;
  }
  if (entry.kind.empty()) return true;
  if (entry.kind == "ip_prefix") return entry.value == subject.ip_prefix;
  if (entry.kind == "ja4") return entry.value == subject.ja4;
  if (entry.kind == "asn") {
    return subject.asn != 0 && entry.value == std::to_string(subject.asn);
  }
  return false;
}

std::string_view KindLabel(std::string_view kind) {
  if (kind == "ip_prefix") return "network";
  if (kind == "asn") return "AS";
  return kind == "ja4" ? "JA4" : kind;
}

}  // namespace

std::optional<std::pair<std::string, std::string>> DominantSignature(
    const std::vector<AttackSample>& samples) {
  if (samples.size() < kMinSamples) return std::nullopt;
  const auto dominant = [&](auto key) -> std::optional<std::string> {
    std::unordered_map<std::string, std::size_t> counts;
    for (const AttackSample& sample : samples) {
      std::string value = key(sample);
      if (!value.empty()) ++counts[std::move(value)];
    }
    for (const auto& [value, count] : counts) {
      if (static_cast<double>(count) >=
          kDominantShare * static_cast<double>(samples.size())) {
        return value;
      }
    }
    return std::nullopt;
  };
  if (auto value =
          dominant([](const AttackSample& s) { return s.ip_prefix; })) {
    return std::pair<std::string, std::string>{"ip_prefix", std::move(*value)};
  }
  if (auto value = dominant([](const AttackSample& s) {
        return s.asn == 0 ? std::string() : std::to_string(s.asn);
      })) {
    return std::pair<std::string, std::string>{"asn", std::move(*value)};
  }
  if (auto value = dominant([](const AttackSample& s) { return s.ja4; })) {
    return std::pair<std::string, std::string>{"ja4", std::move(*value)};
  }
  return std::nullopt;
}

namespace {}  // namespace

AttackMode::AttackMode(int64_t auto_rps, int64_t auto_duration_seconds)
    : auto_rps_(auto_rps),
      auto_duration_seconds_(auto_duration_seconds),
      auto_params_(auto_rps > 0
                       ? GcraParams::FromRate(auto_rps, kNanosPerSecond,
                                              auto_rps * kAutoWindowSeconds)
                       : GcraParams{}) {}

bool AttackMode::Active(const AttackSubject& subject, int64_t now) const {
  if (count_.load(std::memory_order_relaxed) == 0) return false;
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  return std::ranges::any_of(entries_, [&subject, now](const AttackEntry& e) {
    return Matches(e, subject, now);
  });
}

void AttackMode::Sample(const AttackSubject& subject) {
  SampleShard& shard =
      samples_[std::hash<std::string_view>{}(subject.host) % kSampleShards];
  const std::scoped_lock lock(shard.mutex);
  auto it = shard.rings.find(std::string(subject.host));
  if (it == shard.rings.end()) {
    if (shard.rings.size() >= kSampledHostsPerShard) {
      shard.rings.clear();
      shard.next.clear();
    }
    it = shard.rings
             .emplace(std::string(subject.host), std::vector<AttackSample>())
             .first;
    it->second.reserve(kSampleRing);
  }
  AttackSample sample{std::string(subject.ip_prefix), std::string(subject.ja4),
                      subject.asn};
  std::vector<AttackSample>& ring = it->second;
  // Every request until the ring is full (a small site trips after a few
  // dozen), then every kSampleEvery-th per thread.
  if (ring.size() < kSampleRing) {
    ring.push_back(std::move(sample));
    return;
  }
  thread_local uint32_t tick = 0;
  if (++tick % kSampleEvery != 0) return;
  std::size_t& next = shard.next[std::string(subject.host)];
  ring[next] = std::move(sample);
  next = (next + 1) % kSampleRing;
}

std::vector<AttackSample> AttackMode::TakeSamples(std::string_view host) {
  SampleShard& shard =
      samples_[std::hash<std::string_view>{}(host) % kSampleShards];
  const std::scoped_lock lock(shard.mutex);
  std::vector<AttackSample> out;
  if (const auto it = shard.rings.find(std::string(host));
      it != shard.rings.end()) {
    out = std::move(it->second);
    shard.rings.erase(it);
  }
  shard.next.erase(std::string(host));
  return out;
}

bool AttackMode::CountRequest(const AttackSubject& subject, int64_t now,
                              int64_t now_ns, RateLimitStore* store) {
  const std::string_view host = subject.host;
  if (auto_rps_ <= 0 || host.empty()) return false;
  Sample(subject);
  const std::string key = std::format("attack\x1f{}", host);
  if (store->Check(key, auto_params_, now_ns).allowed) return false;
  // The whole host is on already (another worker got here first).
  if (Active(host, now)) return false;
  AttackEntry entry;
  entry.host = std::string(host);
  entry.source = "auto";
  entry.since = now;
  entry.until = now + auto_duration_seconds_;
  std::size_t signatures = 0;
  {
    const std::scoped_lock lock(mutex_);
    signatures = static_cast<std::size_t>(
        std::ranges::count_if(entries_, [&](const AttackEntry& e) {
          return e.host == entry.host && !e.kind.empty();
        }));
  }
  if (signatures < kMaxSignaturesPerHost) {
    if (auto signature = DominantSignature(TakeSamples(host))) {
      entry.kind = std::move(signature->first);
      entry.value = std::move(signature->second);
    }
  }
  // The next trip needs another stretch of excess from what is left.
  store->Forget(key);
  std::string error;
  const AttackEntry enabled = entry;
  if (!Enable(std::move(entry), now, &error)) return false;
  GlobalMetrics().attack_auto_activations.Inc();
  if (enabled.kind.empty()) {
    log::Warn("under-attack mode on for {} for {}s: over {} requests/s", host,
              auto_duration_seconds_, auto_rps_);
  } else {
    log::Warn(
        "under-attack mode on for {} {} on {} for {}s: over {} "
        "requests/s",
        KindLabel(enabled.kind), enabled.value, host, auto_duration_seconds_,
        auto_rps_);
  }
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
  const auto it =
      std::ranges::find_if(entries_, [&entry](const AttackEntry& e) {
        return e.host == entry.host && e.kind == entry.kind &&
               e.value == entry.value;
      });
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
