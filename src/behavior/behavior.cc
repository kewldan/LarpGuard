#include "behavior/behavior.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace bot_shield {
namespace {

// Thresholds of the behaviour signals (weights are in the library).
constexpr std::size_t kRegularMinRequests = 16;
constexpr double kRegularMaxVariation = 0.1;  // stddev / mean of intervals.
constexpr int64_t kRegularMaxMeanMs = 30'000;
constexpr int kNotFoundMinRequests = 20;
constexpr int kApiMinRequests = 10;
constexpr int kNoAssetsMinPages = 8;
constexpr int kSequentialMinSteps = 10;

constexpr std::array<std::string_view, 16> kAssetExtensions = {
    ".css", ".js",   ".mjs",  ".png",  ".jpg",   ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf",  ".map", ".mp4"};

bool EndsWithAny(std::string_view text,
                 std::span<const std::string_view> suffixes) {
  return std::ranges::any_of(
      suffixes, [text](std::string_view s) { return text.ends_with(s); });
}

// "/item/123" -> pattern "/item/#", id 123. False without a trailing number.
bool SplitTrailingId(std::string_view path, std::string* pattern, int64_t* id) {
  while (path.size() > 1 && path.back() == '/') path.remove_suffix(1);
  std::size_t start = path.size();
  while (start > 0 && path[start - 1] >= '0' && path[start - 1] <= '9') {
    --start;
  }
  const std::size_t digits = path.size() - start;
  if (digits == 0 || digits > 15) return false;
  const auto [ptr, ec] =
      std::from_chars(path.data() + start, path.data() + path.size(), *id);
  if (ec != std::errc()) return false;
  *pattern = std::string(path.substr(0, start)) + "#";
  return true;
}

// The ring holds the last `times.size()` request times in any order.
bool RegularTiming(std::span<const int64_t> times, std::size_t count) {
  if (count < kRegularMinRequests || count < times.size()) return false;
  std::vector<int64_t> sorted(times.begin(), times.end());
  std::ranges::sort(sorted);
  std::vector<double> intervals;
  double sum = 0;
  for (std::size_t i = 1; i < sorted.size(); ++i) {
    intervals.push_back(static_cast<double>(sorted[i] - sorted[i - 1]));
    sum += intervals.back();
  }
  const double mean = sum / static_cast<double>(intervals.size());
  if (mean <= 0 || mean > static_cast<double>(kRegularMaxMeanMs)) return false;
  double variance = 0;
  for (const double interval : intervals) {
    variance += (interval - mean) * (interval - mean);
  }
  variance /= static_cast<double>(intervals.size());
  return std::sqrt(variance) / mean < kRegularMaxVariation;
}

}  // namespace

RequestFacts ClassifyRequest(std::string_view method, std::string_view path,
                             std::string_view sec_fetch_mode,
                             std::string_view sec_fetch_dest,
                             std::string_view accept,
                             std::string_view x_requested_with) {
  RequestFacts facts;
  facts.path = path;
  const bool get = method == "GET" || method == "HEAD";
  if (sec_fetch_dest == "script" || sec_fetch_dest == "style" ||
      sec_fetch_dest == "image" || sec_fetch_dest == "font" ||
      (get && EndsWithAny(path, kAssetExtensions))) {
    facts.asset = true;
    return facts;
  }
  if (get && (sec_fetch_mode == "navigate" ||
              (sec_fetch_mode.empty() &&
               accept.find("text/html") != std::string_view::npos))) {
    facts.navigation = true;
    return facts;
  }
  facts.api = sec_fetch_mode == "cors" || !x_requested_with.empty() ||
              path.starts_with("/api/") || path.starts_with("/graphql") ||
              accept.find("application/json") != std::string_view::npos;
  return facts;
}

BehaviorStore::BehaviorStore(BehaviorSettings settings)
    : settings_(settings),
      max_per_shard_(std::max<std::size_t>(1, settings.max_clients / kShards)) {
}

BehaviorStore::Shard& BehaviorStore::ShardFor(std::string_view key) {
  return shards_[std::hash<std::string_view>{}(key) % kShards];
}

const BehaviorStore::Shard& BehaviorStore::ShardFor(
    std::string_view key) const {
  return shards_[std::hash<std::string_view>{}(key) % kShards];
}

void BehaviorStore::Sweep(Shard& shard, int64_t now_ms) const {
  const int64_t window_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(settings_.window)
          .count();
  std::erase_if(shard.clients, [&](const auto& entry) {
    return now_ms - entry.second.last_seen > window_ms;
  });
  std::erase_if(shard.traps,
                [&](const auto& entry) { return entry.second <= now_ms; });
}

bool BehaviorStore::HostServesAssets(std::string_view host) const {
  const std::scoped_lock lock(hosts_mutex_);
  return asset_hosts_.contains(std::string(host));
}

void BehaviorStore::OnRequest(std::string_view client, std::string_view host,
                              const RequestFacts& facts, int64_t now_ms,
                              std::vector<std::string>* signals) {
  if (facts.asset) {
    const std::scoped_lock lock(hosts_mutex_);
    // Bounded by the number of hosts the gateway terminates.
    if (asset_hosts_.size() < 100'000) asset_hosts_.emplace(host);
  }
  const bool assets_expected = facts.navigation && HostServesAssets(host);

  Shard& shard = ShardFor(client);
  const std::scoped_lock lock(shard.mutex);
  auto it = shard.clients.find(std::string(client));
  if (it == shard.clients.end()) {
    if (++shard.inserts % 4096 == 0 || shard.clients.size() >= max_per_shard_) {
      Sweep(shard, now_ms);
    }
    if (shard.clients.size() >= max_per_shard_) {
      untracked_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    it = shard.clients.emplace(std::string(client), Client{}).first;
    it->second.window_start = now_ms;
  }
  Client& state = it->second;
  const int64_t window_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(settings_.window)
          .count();
  if (now_ms - state.window_start > window_ms) {
    state = Client{};
    state.window_start = now_ms;
  }
  state.last_seen = now_ms;
  ++state.requests;
  state.navigations += facts.navigation ? 1 : 0;
  state.api += facts.api ? 1 : 0;
  state.assets += facts.asset ? 1 : 0;
  state.times[state.times_count % kTimes] = now_ms;
  ++state.times_count;

  std::string pattern;
  int64_t id = 0;
  if (!facts.asset && SplitTrailingId(facts.path, &pattern, &id)) {
    if (pattern == state.id_pattern && id == state.last_id + 1) {
      ++state.id_steps;
    } else if (pattern != state.id_pattern) {
      state.id_pattern = std::move(pattern);
      state.id_steps = 0;
    }
    state.last_id = id;
  }

  if (RegularTiming(state.times, state.times_count)) {
    signals->emplace_back("behavior_regular_timing");
  }
  if (state.requests >= kNotFoundMinRequests &&
      state.not_found * 2 > state.requests) {
    signals->emplace_back("behavior_not_found");
  }
  if (state.api >= kApiMinRequests && state.navigations == 0 &&
      state.assets == 0) {
    signals->emplace_back("behavior_api_without_page");
  }
  if (assets_expected && state.navigations >= kNoAssetsMinPages &&
      state.assets == 0) {
    signals->emplace_back("behavior_no_assets");
  }
  if (state.id_steps >= kSequentialMinSteps) {
    signals->emplace_back("behavior_sequential_ids");
  }
}

void BehaviorStore::OnStatus(std::string_view client, int status,
                             int64_t /*now_ms*/) {
  if (status != 404 && status != 410) return;
  Shard& shard = ShardFor(client);
  const std::scoped_lock lock(shard.mutex);
  if (const auto it = shard.clients.find(std::string(client));
      it != shard.clients.end()) {
    ++it->second.not_found;
  }
}

void BehaviorStore::Trap(const std::vector<std::string>& keys, int64_t now_ms,
                         int64_t until_ms) {
  for (const std::string& key : keys) {
    Shard& shard = ShardFor(key);
    const std::scoped_lock lock(shard.mutex);
    if (shard.traps.size() >= max_per_shard_) Sweep(shard, now_ms);
    if (shard.traps.size() >= max_per_shard_ && !shard.traps.contains(key)) {
      untracked_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    int64_t& until = shard.traps[key];
    until = std::max(until, until_ms);
  }
}

bool BehaviorStore::Trapped(const std::vector<std::string>& keys,
                            int64_t now_ms) const {
  return std::ranges::any_of(keys, [&](const std::string& key) {
    const Shard& shard = ShardFor(key);
    const std::scoped_lock lock(shard.mutex);
    const auto it = shard.traps.find(key);
    return it != shard.traps.end() && it->second > now_ms;
  });
}

std::size_t BehaviorStore::size() const {
  std::size_t total = 0;
  for (const Shard& shard : shards_) {
    const std::scoped_lock lock(shard.mutex);
    total += shard.clients.size() + shard.traps.size();
  }
  return total;
}

}  // namespace bot_shield
