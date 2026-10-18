#ifndef BOT_SHIELD_BEHAVIOR_BEHAVIOR_H_
#define BOT_SHIELD_BEHAVIOR_BEHAVIOR_H_

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bot_shield {

// What one request tells about its client's behaviour.
struct RequestFacts {
  std::string_view path;  // Without the query.
  bool navigation = false;
  bool api = false;
  bool asset = false;
};

// Classifies a request from its path and fetch metadata.
RequestFacts ClassifyRequest(std::string_view method, std::string_view path,
                             std::string_view sec_fetch_mode,
                             std::string_view sec_fetch_dest,
                             std::string_view accept,
                             std::string_view x_requested_with);

struct BehaviorSettings {
  // Counters cover this window, then start over.
  std::chrono::seconds window{600};
  std::size_t max_clients = 500'000;
};

// Recent behaviour of clients (docs/architecture.md, 5.4) and honeypot
// marks (6.3), shared by all workers like the rate limit store. A client is
// one TLS fingerprint in one network on one host; honeypot marks are kept
// per address and per fingerprint+network, across hosts.
class BehaviorStore {
 public:
  explicit BehaviorStore(BehaviorSettings settings = {});

  BehaviorStore(const BehaviorStore&) = delete;
  BehaviorStore& operator=(const BehaviorStore&) = delete;

  // Records a request and appends the behaviour signals it shows
  // ("behavior_regular_timing", ...) to `signals`. `now_ms`: steady clock.
  void OnRequest(std::string_view client, std::string_view host,
                 const RequestFacts& facts, int64_t now_ms,
                 std::vector<std::string>* signals);
  // Response status of a request recorded by OnRequest.
  void OnStatus(std::string_view client, int status, int64_t now_ms);

  // Honeypot: marks `keys` (address, fingerprint+network) until `until_ms`.
  void Trap(const std::vector<std::string>& keys, int64_t now_ms,
            int64_t until_ms);
  bool Trapped(const std::vector<std::string>& keys, int64_t now_ms) const;

  std::size_t size() const;
  uint64_t untracked() const { return untracked_.load(); }

 private:
  static constexpr std::size_t kShards = 64;
  static constexpr std::size_t kTimes = 16;

  struct Client {
    int64_t window_start = 0;
    int64_t last_seen = 0;
    int requests = 0;
    int not_found = 0;
    int navigations = 0;
    int api = 0;
    int assets = 0;
    // Last request times, for the regularity check.
    std::array<int64_t, kTimes> times{};
    std::size_t times_count = 0;
    // Enumeration: same path apart from a number that grows by one.
    std::string id_pattern;
    int64_t last_id = -1;
    int id_steps = 0;
  };
  struct Shard {
    mutable std::mutex mutex;
    std::unordered_map<std::string, Client> clients;
    std::unordered_map<std::string, int64_t> traps;  // Key -> until (ms).
    std::size_t inserts = 0;
  };

  Shard& ShardFor(std::string_view key);
  const Shard& ShardFor(std::string_view key) const;
  void Sweep(Shard& shard, int64_t now_ms) const;
  bool HostServesAssets(std::string_view host) const;

  const BehaviorSettings settings_;
  const std::size_t max_per_shard_;
  std::array<Shard, kShards> shards_;
  mutable std::mutex hosts_mutex_;
  // Hosts whose static files go through the gateway (seen asset requests).
  std::unordered_set<std::string> asset_hosts_;
  std::atomic<uint64_t> untracked_{0};
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_BEHAVIOR_BEHAVIOR_H_
