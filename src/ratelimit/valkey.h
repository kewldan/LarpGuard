#ifndef BOT_SHIELD_RATELIMIT_VALKEY_H_
#define BOT_SHIELD_RATELIMIT_VALKEY_H_

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "ratelimit/gcra.h"
#include "ratelimit/store.h"

namespace bot_shield {

// One RESP2 reply.
struct RespValue {
  enum class Type { kSimple, kError, kInteger, kBulk, kNull, kArray };
  Type type = Type::kNull;
  std::string text;  // Simple, error, bulk.
  int64_t integer = 0;
  std::vector<RespValue> items;
};

// RESP2 encoding and parsing (exposed for tests).
std::string RespCommand(const std::vector<std::string>& args);
// Parses one reply from the front of `buffer`; 0 when incomplete, -1 when
// malformed, else the bytes used.
int64_t RespParse(std::string_view buffer, RespValue* value);

// A blocking connection to Valkey (or Redis) with deadlines on every
// read and write. Only for background threads.
class ValkeyConnection {
 public:
  ValkeyConnection() = default;
  ~ValkeyConnection();
  ValkeyConnection(const ValkeyConnection&) = delete;
  ValkeyConnection& operator=(const ValkeyConnection&) = delete;

  bool Connect(const std::string& host, uint16_t port,
               std::chrono::milliseconds timeout, std::string* error);
  bool connected() const { return fd_ >= 0; }
  void Close();
  // Sends the commands in one write and reads one reply each (pipelined).
  // False (and closed) on a network error or timeout; error replies are
  // values, not failures.
  bool Run(const std::vector<std::vector<std::string>>& commands,
           std::vector<RespValue>* replies, std::string* error);

 private:
  int fd_ = -1;
  std::chrono::milliseconds timeout_{50};
  std::string buffer_;
};

struct ValkeySettings {
  std::string host;
  uint16_t port = 6379;
  std::string password;
  // Prepended to every key (a SHA-256 of the limit's key: addresses and
  // header values stay here): gateways sharing a Valkey share limits.
  std::string prefix = "botshield:";
  // Deadline of a strict check (connect, write, read); over it the request
  // is decided by the local state instead.
  std::chrono::milliseconds timeout{50};
  // How often synced limits exchange their counts.
  std::chrono::milliseconds sync_interval{200};
  // Strict checks waiting for the thread; beyond, decided locally.
  std::size_t max_queue = 4096;
};

// A strict limit to check in Valkey for one request.
struct StrictCheck {
  std::string name;
  std::string key;
  GcraParams params;
  int64_t burst = 0;
  int64_t window_seconds = 0;
};

// Rate limits shared by several gateways through Valkey (ADR-005, 8.2):
//  - synced: each request is decided locally (RateLimitStore); a background
//    thread sends every key's local count each sync_interval and raises the
//    local state to the global one, so the gateways converge (±5-10 %);
//  - strict: the request waits for an atomic GCRA step in Valkey (Lua),
//    run by this class's thread, never the worker's.
// When Valkey is down both act like local limits; nothing is refused for
// lack of Valkey.
class ValkeyLimiter {
 public:
  using StrictDone = std::function<void(std::optional<GcraResult> result,
                                        std::size_t refused_index)>;

  // `store` is the local state that synced limits raise.
  ValkeyLimiter(ValkeySettings settings, RateLimitStore* store);
  ~ValkeyLimiter();
  ValkeyLimiter(const ValkeyLimiter&) = delete;
  ValkeyLimiter& operator=(const ValkeyLimiter&) = delete;

  // Hot path: a synced key let one request through locally.
  void NoteSynced(std::string_view key, const GcraParams& params);

  // Queues strict checks (all of one request). `done` runs on the
  // limiter's thread: with the first refusing check's result and index,
  // with an allowed result (index = checks.size()) when every check
  // passed, or with nullopt when Valkey could not decide (down, timeout,
  // queue full: decide locally). False when not queued (done not called).
  bool Strict(std::vector<StrictCheck> checks, StrictDone done);

  bool available() const { return up_.load(std::memory_order_relaxed); }

 private:
  struct Pending {
    GcraParams params;
    int64_t count = 0;
  };
  struct SyncShard {
    std::mutex mutex;
    std::unordered_map<std::string, Pending> keys;
  };
  struct Job {
    std::vector<StrictCheck> checks;
    StrictDone done;
  };
  static constexpr std::size_t kSyncShards = 16;

  void Run(const std::stop_token& stop);
  bool EnsureConnected();
  void RunStrict(Job& job);
  void Sync();

  const ValkeySettings settings_;
  RateLimitStore* store_;
  std::atomic<bool> up_{false};
  std::array<SyncShard, kSyncShards> sync_;
  std::mutex mutex_;
  std::condition_variable_any wake_;
  std::deque<Job> queue_;
  ValkeyConnection connection_;  // The thread's only.
  std::chrono::steady_clock::time_point next_sync_;
  std::chrono::steady_clock::time_point retry_at_;
  std::jthread thread_;  // Last: joined first.
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_RATELIMIT_VALKEY_H_
