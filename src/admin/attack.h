#ifndef BOT_SHIELD_ADMIN_ATTACK_H_
#define BOT_SHIELD_ADMIN_ATTACK_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
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
  // Automatic entries: the requests/s threshold that tripped (per host, or
  // across all hosts for host "*").
  int64_t threshold = 0;
};

// An entry as it was switched on, kept after it ends (GET /attack).
struct AttackRecord {
  AttackEntry entry;
  int64_t ended = 0;  // Unix seconds; 0 while in effect.
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
// stays above a threshold (or for every host when the total rate does):
// then, when most of the recent requests share a signature (one network,
// AS or TLS stack), only those clients; otherwise the whole host. Clients
// already covered no longer count, so an attack that goes on from
// elsewhere trips again, up to the whole host. Shared by all workers;
// Active() skips the lock while nothing is under attack (the common case).
// Entries and the history of activations survive restarts in a state file
// written by SaveIfChanged() off the workers.
class AttackMode {
 public:
  static constexpr std::size_t kMaxEntries = 1024;
  static constexpr std::size_t kMaxHistory = 200;

  // `auto_rps` (per host) and `auto_rps_total` (all hosts together) 0 turn
  // automatic activation off; `state_file` "" keeps everything in memory.
  AttackMode(int64_t auto_rps, int64_t auto_rps_total,
             int64_t auto_duration_seconds, std::string state_file = "");

  // Reads the state file (missing: nothing); expired entries are dropped.
  bool Load(int64_t now, std::string* error);
  // Writes the state file if anything changed since the last write. Call
  // from a thread that may block (not a worker).
  bool SaveIfChanged(int64_t now, std::string* error);

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
  bool Disable(std::string_view host, int64_t now);
  // Entries still in effect at `now`.
  std::vector<AttackEntry> Entries(int64_t now) const;
  // Activations, newest first, ended ones included.
  std::vector<AttackRecord> History(int64_t now) const;

  int64_t auto_rps() const { return auto_rps_; }
  int64_t auto_rps_total() const { return auto_rps_total_; }

  // Called on the worker that switched a host on automatically (once per
  // switch); must not block. Set before traffic starts.
  void set_on_auto(std::function<void(const AttackEntry& entry)> on_auto) {
    on_auto_ = std::move(on_auto);
  }

 private:
  // Drops expired entries and ends their records; needs `mutex_`.
  void SweepLocked(int64_t now) const;
  // Ends the open record of the entry; needs `mutex_`.
  void EndRecordLocked(const AttackEntry& entry, int64_t ended) const;
  void UpdateCountLocked() const;
  // Counts a request against the threshold of `scope` (a host, or "*" for
  // the total) and switches it on when exceeded.
  bool CountScope(const AttackSubject& subject, std::string_view scope,
                  const GcraParams& params, int64_t threshold, int64_t now,
                  int64_t now_ns, RateLimitStore* store);
  // Records a request under `scope` (sparser once its ring is full).
  void Sample(std::string_view scope, const AttackSubject& subject);
  // Takes and clears the samples of `scope`.
  std::vector<AttackSample> TakeSamples(std::string_view scope);

  static constexpr std::size_t kSampleShards = 16;
  struct SampleShard {
    std::mutex mutex;
    // Host -> ring of recent samples and the next slot.
    std::unordered_map<std::string, std::vector<AttackSample>> rings;
    std::unordered_map<std::string, std::size_t> next;
  };

  const int64_t auto_rps_;
  const int64_t auto_rps_total_;
  const int64_t auto_duration_seconds_;
  const GcraParams auto_params_;
  const GcraParams total_params_;
  const std::string state_file_;
  std::function<void(const AttackEntry& entry)> on_auto_;
  mutable std::mutex mutex_;
  mutable std::vector<AttackEntry> entries_;
  mutable std::deque<AttackRecord> history_;  // Newest first.
  // Bumped on every change; `saved_` is the version on disk.
  mutable uint64_t version_ = 0;
  uint64_t saved_ = 0;
  mutable std::atomic<std::size_t> count_{0};
  std::array<SampleShard, kSampleShards> samples_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_ATTACK_H_
