#include "ratelimit/store.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

#include "ratelimit/gcra.h"

namespace bot_shield {
namespace {

std::size_t ShardOf(std::string_view key, std::size_t shards) {
  return std::hash<std::string_view>{}(key) % shards;
}

}  // namespace

RateLimitStore::RateLimitStore(std::size_t max_keys)
    : max_keys_per_shard_(std::max<std::size_t>(1, max_keys / kShards)) {}

void RateLimitStore::Sweep(Shard& shard, int64_t now_ns) {
  // A TAT in the past is the same as no state at all.
  std::erase_if(shard.tats,
                [now_ns](const auto& entry) { return entry.second <= now_ns; });
}

GcraResult RateLimitStore::Check(std::string_view key, const GcraParams& params,
                                 int64_t now_ns) {
  Shard& shard = shards_[ShardOf(key, kShards)];
  std::scoped_lock lock(shard.mutex);
  // Heterogeneous lookup would avoid this copy; keys are short.
  const std::string owned(key);
  auto it = shard.tats.find(owned);
  if (it == shard.tats.end()) {
    if (++shard.inserts % kSweepEvery == 0 ||
        shard.tats.size() >= max_keys_per_shard_) {
      Sweep(shard, now_ns);
    }
    if (shard.tats.size() >= max_keys_per_shard_) {
      // Out of room: let the request through untracked.
      untracked_.fetch_add(1, std::memory_order_relaxed);
      int64_t fresh = 0;
      return GcraCheck(&fresh, now_ns, params);
    }
    it = shard.tats.emplace(owned, 0).first;
  }
  return GcraCheck(&it->second, now_ns, params);
}

GcraResult RateLimitStore::Peek(std::string_view key, const GcraParams& params,
                                int64_t now_ns) const {
  const Shard& shard = shards_[ShardOf(key, kShards)];
  std::scoped_lock lock(shard.mutex);
  const auto it = shard.tats.find(std::string(key));
  int64_t tat = it == shard.tats.end() ? 0 : it->second;
  return GcraCheck(&tat, now_ns, params);
}

void RateLimitStore::Forget(std::string_view key) {
  Shard& shard = shards_[ShardOf(key, kShards)];
  std::scoped_lock lock(shard.mutex);
  shard.tats.erase(std::string(key));
}

void RateLimitStore::Raise(std::string_view key, int64_t tat_ns) {
  Shard& shard = shards_[ShardOf(key, kShards)];
  std::scoped_lock lock(shard.mutex);
  const std::string owned(key);
  auto it = shard.tats.find(owned);
  if (it == shard.tats.end()) {
    if (shard.tats.size() >= max_keys_per_shard_) return;
    it = shard.tats.emplace(owned, 0).first;
  }
  it->second = std::max(it->second, tat_ns);
}

std::size_t RateLimitStore::size() const {
  std::size_t total = 0;
  for (const Shard& shard : shards_) {
    std::scoped_lock lock(shard.mutex);
    total += shard.tats.size();
  }
  return total;
}

bool ConnectionCounter::Acquire(std::string_view key, std::size_t limit) {
  Shard& shard = shards_[ShardOf(key, kShards)];
  std::scoped_lock lock(shard.mutex);
  std::size_t& open = shard.open[std::string(key)];
  if (open >= limit) {
    if (open == 0) shard.open.erase(std::string(key));
    return false;
  }
  ++open;
  return true;
}

void ConnectionCounter::Release(std::string_view key) {
  Shard& shard = shards_[ShardOf(key, kShards)];
  std::scoped_lock lock(shard.mutex);
  const auto it = shard.open.find(std::string(key));
  if (it == shard.open.end()) return;
  if (--it->second == 0) shard.open.erase(it);
}

}  // namespace bot_shield
