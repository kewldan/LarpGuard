#ifndef BOT_SHIELD_SERVER_HEALTH_H_
#define BOT_SHIELD_SERVER_HEALTH_H_

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

namespace bot_shield {

// Liveness of the worker event loops. Each worker beats from a timer on its
// own loop; a worker whose loop is stuck (a blocking call, a busy loop)
// stops beating, and /health and the systemd watchdog report it.
class Heartbeats {
 public:
  static constexpr std::chrono::milliseconds kInterval{500};
  // Older than this, a worker counts as stalled.
  static constexpr std::chrono::milliseconds kMaxAge{5000};

  // All workers start as just beaten at `now_ms` (steady clock).
  Heartbeats(int workers, int64_t now_ms);

  // `generation`: the verdict set the worker's loop saw at this beat
  // (every request after it uses that set or a newer one).
  void Beat(int worker, int64_t now_ms, uint64_t generation = 0);
  // A worker that has not beaten for longer than kMaxAge, or -1.
  int Stalled(int64_t now_ms) const;
  int workers() const { return workers_; }
  int64_t last_beat(int worker) const {
    return beats_[worker].load(std::memory_order_relaxed);
  }
  uint64_t generation(int worker) const {
    return generations_[worker].load(std::memory_order_relaxed);
  }

 private:
  int workers_;
  std::unique_ptr<std::atomic<int64_t>[]> beats_;
  std::unique_ptr<std::atomic<uint64_t>[]> generations_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_HEALTH_H_
