#ifndef BOT_SHIELD_ADMIN_ATTACK_H_
#define BOT_SHIELD_ADMIN_ATTACK_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
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
  // Only clients with this signature: "ip_prefix" (as in events), "asn" or
  // "ja4", with `value`. Empty: every client of the host.
  std::string kind;
  std::string value;
};

// What an entry is matched against: the request's host and the client's
// signature parts (empty or 0 when unknown).
struct AttackSubject {
  std::string_view host;
  std::string_view ip_prefix;
  std::string_view ja4;
  uint32_t asn = 0;
};

// One sampled request of a host, for picking the attack's signature.
struct AttackSample {
  std::string ip_prefix;
  std::string ja4;
  uint32_t asn = 0;
};

// The signature most of `samples` share, if one does (kind and value):
// the narrowest first (ip_prefix, then asn, then ja4). Nullopt with too
// few samples or none dominant: a spread-out attack.
std::optional<std::pair<std::string, std::string>> DominantSignature(
    const std::vector<AttackSample>& samples);

// Under-attack mode: on these hosts every client without a valid clearance
// token gets the JS challenge, whatever its score and the host's mode.
// Switched by the admin API, or automatically for a host whose request rate
// stays above a threshold: then, when most of its recent requests share a
// signature (one network, AS or TLS stack), only those clients; otherwise
// the whole host. Clients already covered no longer count, so an attack
// that goes on from elsewhere trips again, up to the whole host. Shared by
// all workers; Active() skips the lock while nothing is under attack (the
// common case). Kept in memory only.
class AttackMode {
 public:
  static constexpr std::size_t kMaxEntries = 1024;

  // `auto_rps` 0 turns automatic activation off.
  AttackMode(int64_t auto_rps, int64_t auto_duration_seconds);

  AttackMode(const AttackMode&) = delete;
  AttackMode& operator=(const AttackMode&) = delete;

  // `subject.host` is normalized, without a port. A bare host matches only
  // whole-host entries.
  bool Active(const AttackSubject& subject, int64_t now) const;
  bool Active(std::string_view host, int64_t now) const {
    return Active(AttackSubject{.host = host}, now);
  }

  // Counts a request not covered by an entry (call it only when Active()
  // said no) and switches the host on once its rate has been above
  // auto_rps for about ten seconds (a burst of ten seconds' worth): for the
  // dominant signature of its recent requests if there is one. Returns
  // true when this call switched something on.
  bool CountRequest(const AttackSubject& subject, int64_t now, int64_t now_ns,
                    RateLimitStore* store);
  bool CountRequest(std::string_view host, int64_t now, int64_t now_ns,
                    RateLimitStore* store) {
    return CountRequest(AttackSubject{.host = host}, now, now_ns, store);
  }

  // Adds the entry or replaces the one for the same host. False (with
  // `error`) for an invalid host or when the table is full.
  // Adds the entry or replaces the one for the same host and signature.
  bool Enable(AttackEntry entry, int64_t now, std::string* error);
  // Every entry of the host, with or without a signature.
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
  // Records a request of a host (sparser once its ring is full).
  void Sample(const AttackSubject& subject);
  // Takes and clears the host's samples.
  std::vector<AttackSample> TakeSamples(std::string_view host);

  static constexpr std::size_t kSampleShards = 16;
  struct SampleShard {
    std::mutex mutex;
    // Host -> ring of recent samples and the next slot.
    std::unordered_map<std::string, std::vector<AttackSample>> rings;
    std::unordered_map<std::string, std::size_t> next;
  };

  const int64_t auto_rps_;
  const int64_t auto_duration_seconds_;
  const GcraParams auto_params_;
  std::function<void(const AttackEntry& entry)> on_auto_;
  mutable std::mutex mutex_;
  mutable std::vector<AttackEntry> entries_;
  mutable std::atomic<std::size_t> count_{0};
  std::array<SampleShard, kSampleShards> samples_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_ATTACK_H_
