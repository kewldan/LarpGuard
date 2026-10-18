#include "server/health.h"

#include <atomic>
#include <cstdint>
#include <memory>

namespace bot_shield {

Heartbeats::Heartbeats(int workers, int64_t now_ms)
    : workers_(workers),
      beats_(std::make_unique<std::atomic<int64_t>[]>(workers)) {
  for (int i = 0; i < workers_; ++i) beats_[i].store(now_ms);
}

void Heartbeats::Beat(int worker, int64_t now_ms) {
  if (worker >= 0 && worker < workers_) {
    beats_[worker].store(now_ms, std::memory_order_relaxed);
  }
}

int Heartbeats::Stalled(int64_t now_ms) const {
  for (int i = 0; i < workers_; ++i) {
    if (now_ms - beats_[i].load(std::memory_order_relaxed) > kMaxAge.count()) {
      return i;
    }
  }
  return -1;
}

}  // namespace bot_shield
