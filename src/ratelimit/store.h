#ifndef BOT_SHIELD_RATELIMIT_STORE_H_
#define BOT_SHIELD_RATELIMIT_STORE_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "ratelimit/gcra.h"

namespace bot_shield {

// Process-wide GCRA state shared by all workers. A client's connections may
// land on any worker (SO_REUSEPORT), so per-worker state would multiply
// every limit by the worker count. The map is split into shards with their
// own mutex; a check holds one shard lock for a hash lookup and two
// comparisons.
class RateLimitStore {
 public:
  // Above this many keys new keys are not tracked (fail open, counted);
  // keys whose state is back to "fresh" are swept regularly.
  explicit RateLimitStore(std::size_t max_keys = 1'000'000);

  RateLimitStore(const RateLimitStore&) = delete;
  RateLimitStore& operator=(const RateLimitStore&) = delete;

  GcraResult Check(std::string_view key, const GcraParams& params,
                   int64_t now_ns);

  std::size_t size() const;
  uint64_t untracked() const { return untracked_.load(); }

 private:
  static constexpr std::size_t kShards = 64;
  // Sweep a shard every this many inserts into it.
  static constexpr std::size_t kSweepEvery = 4096;

  struct Shard {
    mutable std::mutex mutex;
    // Key -> theoretical arrival time.
    std::unordered_map<std::string, int64_t> tats;
    std::size_t inserts = 0;
  };

  static void Sweep(Shard& shard, int64_t now_ns);

  const std::size_t max_keys_per_shard_;
  std::array<Shard, kShards> shards_;
  std::atomic<uint64_t> untracked_{0};
};

// Open connections per key (client IP), shared by all workers.
class ConnectionCounter {
 public:
  // Returns false (and counts nothing) if `key` already has `limit` open.
  bool Acquire(std::string_view key, std::size_t limit);
  void Release(std::string_view key);

 private:
  static constexpr std::size_t kShards = 64;
  struct Shard {
    std::mutex mutex;
    std::unordered_map<std::string, std::size_t> open;
  };
  std::array<Shard, kShards> shards_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_RATELIMIT_STORE_H_
