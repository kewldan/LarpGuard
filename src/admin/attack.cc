#include "admin/attack.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <ios>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
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

bool SameEntry(const AttackEntry& a, const AttackEntry& b) {
  return a.host == b.host && a.kind == b.kind && a.value == b.value;
}

nlohmann::json EntryJson(const AttackEntry& entry) {
  nlohmann::json json = {{"host", entry.host},
                         {"source", entry.source},
                         {"since", entry.since},
                         {"until", entry.until}};
  if (!entry.kind.empty()) {
    json["kind"] = entry.kind;
    json["value"] = entry.value;
  }
  if (entry.threshold != 0) json["threshold"] = entry.threshold;
  return json;
}

bool EntryFromJson(const nlohmann::json& json, AttackEntry* entry) {
  if (!json.is_object() || !json.contains("host") ||
      !json["host"].is_string()) {
    return false;
  }
  entry->host = json["host"].get<std::string>();
  entry->source = json.value("source", std::string("admin"));
  entry->since = json.value("since", int64_t{0});
  entry->until = json.value("until", int64_t{0});
  entry->kind = json.value("kind", std::string());
  entry->value = json.value("value", std::string());
  entry->threshold = json.value("threshold", int64_t{0});
  return true;
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

AttackMode::AttackMode(int64_t auto_rps, int64_t auto_rps_total,
                       int64_t auto_duration_seconds, std::string state_file)
    : auto_rps_(auto_rps),
      auto_rps_total_(auto_rps_total),
      auto_duration_seconds_(auto_duration_seconds),
      auto_params_(auto_rps > 0
                       ? GcraParams::FromRate(auto_rps, kNanosPerSecond,
                                              auto_rps * kAutoWindowSeconds)
                       : GcraParams{}),
      total_params_(
          auto_rps_total > 0
              ? GcraParams::FromRate(auto_rps_total, kNanosPerSecond,
                                     auto_rps_total * kAutoWindowSeconds)
              : GcraParams{}),
      state_file_(std::move(state_file)) {}

bool AttackMode::Load(int64_t now, std::string* error) {
  if (state_file_.empty()) return true;
  std::ifstream file(state_file_);
  if (!file) return true;  // First start.
  const nlohmann::json json = nlohmann::json::parse(file, nullptr, false);
  if (json.is_discarded() || !json.is_object()) {
    *error = std::format("{}: not a JSON object", state_file_);
    return false;
  }
  const std::scoped_lock lock(mutex_);
  entries_.clear();
  history_.clear();
  for (const nlohmann::json& item : json.value("history", nlohmann::json())) {
    AttackRecord record;
    if (!EntryFromJson(item, &record.entry)) continue;
    record.ended = item.value("ended", int64_t{0});
    if (history_.size() < kMaxHistory) history_.push_back(std::move(record));
  }
  for (const nlohmann::json& item : json.value("entries", nlohmann::json())) {
    AttackEntry entry;
    if (!EntryFromJson(item, &entry) || entries_.size() >= kMaxEntries) {
      continue;
    }
    entries_.push_back(std::move(entry));
  }
  // What expired while the gateway was down ends at its own deadline.
  for (const AttackEntry& entry : entries_) {
    if (entry.until != 0 && entry.until <= now) {
      EndRecordLocked(entry, entry.until);
    }
  }
  std::erase_if(entries_, [now](const AttackEntry& e) {
    return e.until != 0 && e.until <= now;
  });
  // Open records without an entry (the file was edited): ended now.
  for (AttackRecord& record : history_) {
    if (record.ended == 0 &&
        std::ranges::none_of(entries_, [&](const AttackEntry& e) {
          return SameEntry(e, record.entry);
        })) {
      record.ended = now;
    }
  }
  UpdateCountLocked();
  saved_ = version_;
  return true;
}

bool AttackMode::SaveIfChanged(int64_t now, std::string* error) {
  nlohmann::json json;
  uint64_t version = 0;
  {
    const std::scoped_lock lock(mutex_);
    SweepLocked(now);
    if (state_file_.empty() || version_ == saved_) return true;
    version = version_;
    nlohmann::json entries = nlohmann::json::array();
    for (const AttackEntry& entry : entries_) {
      entries.push_back(EntryJson(entry));
    }
    nlohmann::json history = nlohmann::json::array();
    for (const AttackRecord& record : history_) {
      nlohmann::json item = EntryJson(record.entry);
      if (record.ended != 0) item["ended"] = record.ended;
      history.push_back(std::move(item));
    }
    json = {{"entries", std::move(entries)}, {"history", std::move(history)}};
  }
  const std::string temporary = state_file_ + ".tmp";
  {
    std::ofstream file(temporary, std::ios::trunc);
    file << json.dump(2) << '\n';
    if (!file.flush()) {
      *error = std::format("cannot write {}", temporary);
      return false;
    }
  }
  std::error_code ec;
  std::filesystem::permissions(temporary, std::filesystem::perms(0600), ec);
  std::filesystem::rename(temporary, state_file_, ec);
  if (ec) {
    *error = std::format("cannot replace {}: {}", state_file_, ec.message());
    return false;
  }
  saved_ = version;
  return true;
}

bool AttackMode::Active(const AttackSubject& subject, int64_t now) const {
  if (count_.load(std::memory_order_relaxed) == 0) return false;
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  return std::ranges::any_of(entries_, [&subject, now](const AttackEntry& e) {
    return Matches(e, subject, now);
  });
}

void AttackMode::Sample(std::string_view scope, const AttackSubject& subject) {
  SampleShard& shard =
      samples_[std::hash<std::string_view>{}(scope) % kSampleShards];
  const std::scoped_lock lock(shard.mutex);
  auto it = shard.rings.find(std::string(scope));
  if (it == shard.rings.end()) {
    if (shard.rings.size() >= kSampledHostsPerShard) {
      shard.rings.clear();
      shard.next.clear();
    }
    it = shard.rings.emplace(std::string(scope), std::vector<AttackSample>())
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
  std::size_t& next = shard.next[std::string(scope)];
  ring[next] = std::move(sample);
  next = (next + 1) % kSampleRing;
}

std::vector<AttackSample> AttackMode::TakeSamples(std::string_view scope) {
  SampleShard& shard =
      samples_[std::hash<std::string_view>{}(scope) % kSampleShards];
  const std::scoped_lock lock(shard.mutex);
  std::vector<AttackSample> out;
  if (const auto it = shard.rings.find(std::string(scope));
      it != shard.rings.end()) {
    out = std::move(it->second);
    shard.rings.erase(it);
  }
  shard.next.erase(std::string(scope));
  return out;
}

bool AttackMode::CountRequest(const AttackSubject& subject, int64_t now,
                              int64_t now_ns, RateLimitStore* store) {
  if (subject.host.empty()) return false;
  if (auto_rps_ > 0 && CountScope(subject, subject.host, auto_params_,
                                  auto_rps_, now, now_ns, store)) {
    return true;
  }
  return auto_rps_total_ > 0 && CountScope(subject, "*", total_params_,
                                           auto_rps_total_, now, now_ns, store);
}

bool AttackMode::CountScope(const AttackSubject& subject,
                            std::string_view scope, const GcraParams& params,
                            int64_t threshold, int64_t now, int64_t now_ns,
                            RateLimitStore* store) {
  Sample(scope, subject);
  const std::string key = std::format("attack\x1f{}", scope);
  if (store->Check(key, params, now_ns).allowed) return false;
  // The whole scope is on already (another worker got here first).
  {
    const std::scoped_lock lock(mutex_);
    SweepLocked(now);
    if (std::ranges::any_of(entries_, [&](const AttackEntry& e) {
          return e.kind.empty() &&
                 (e.host == "*" ||
                  (scope != "*" && HostMatches(e.host, scope)));
        })) {
      return false;
    }
  }
  AttackEntry entry;
  entry.host = std::string(scope);
  entry.source = "auto";
  entry.since = now;
  entry.until = now + auto_duration_seconds_;
  entry.threshold = threshold;
  std::size_t signatures = 0;
  {
    const std::scoped_lock lock(mutex_);
    signatures = static_cast<std::size_t>(
        std::ranges::count_if(entries_, [&](const AttackEntry& e) {
          return e.host == entry.host && !e.kind.empty();
        }));
  }
  if (signatures < kMaxSignaturesPerHost) {
    if (auto signature = DominantSignature(TakeSamples(scope))) {
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
  const std::string where =
      scope == "*" ? std::string("all hosts") : std::string(scope);
  const std::string_view total = scope == "*" ? " in total" : "";
  if (enabled.kind.empty()) {
    log::Warn("under-attack mode on for {} for {}s: over {} requests/s{}",
              where, auto_duration_seconds_, threshold, total);
  } else {
    log::Warn(
        "under-attack mode on for {} {} on {} for {}s: over {} "
        "requests/s{}",
        KindLabel(enabled.kind), enabled.value, where, auto_duration_seconds_,
        threshold, total);
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
  const auto it = std::ranges::find_if(
      entries_, [&entry](const AttackEntry& e) { return SameEntry(e, entry); });
  if (it == entries_.end() && entries_.size() >= kMaxEntries) {
    *error = "too many hosts under attack";
    return false;
  }
  // A renewal (same host and signature) extends its open record.
  const auto record =
      std::ranges::find_if(history_, [&entry](const AttackRecord& r) {
        return r.ended == 0 && SameEntry(r.entry, entry);
      });
  if (it != entries_.end() && record != history_.end()) {
    record->entry.until = entry.until;
    record->entry.source = entry.source;
  } else {
    history_.push_front(AttackRecord{entry, 0});
    if (history_.size() > kMaxHistory) history_.pop_back();
  }
  if (it != entries_.end()) {
    *it = std::move(entry);
  } else {
    entries_.push_back(std::move(entry));
  }
  UpdateCountLocked();
  return true;
}

bool AttackMode::Disable(std::string_view host, int64_t now) {
  const std::string normalized = NormalizeHost(host);
  const std::scoped_lock lock(mutex_);
  for (const AttackEntry& entry : entries_) {
    if (entry.host == normalized) EndRecordLocked(entry, now);
  }
  const std::size_t removed = std::erase_if(
      entries_,
      [&normalized](const AttackEntry& e) { return e.host == normalized; });
  UpdateCountLocked();
  return removed > 0;
}

std::vector<AttackEntry> AttackMode::Entries(int64_t now) const {
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  return entries_;
}

std::vector<AttackRecord> AttackMode::History(int64_t now) const {
  const std::scoped_lock lock(mutex_);
  SweepLocked(now);
  return {history_.begin(), history_.end()};
}

void AttackMode::EndRecordLocked(const AttackEntry& entry,
                                 int64_t ended) const {
  for (AttackRecord& record : history_) {
    if (record.ended == 0 && SameEntry(record.entry, entry)) {
      record.ended = ended;
      ++version_;
    }
  }
}

void AttackMode::UpdateCountLocked() const {
  ++version_;
  count_.store(entries_.size(), std::memory_order_relaxed);
  GlobalMetrics().attack_hosts.Set(static_cast<int64_t>(entries_.size()));
}

void AttackMode::SweepLocked(int64_t now) const {
  bool any = false;
  for (const AttackEntry& entry : entries_) {
    if (entry.until != 0 && entry.until <= now) {
      EndRecordLocked(entry, entry.until);
      any = true;
    }
  }
  if (!any) return;
  std::erase_if(entries_, [now](const auto& e) {
    return e.until != 0 && e.until <= now;
  });
  UpdateCountLocked();
}

}  // namespace bot_shield
