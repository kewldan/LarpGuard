#include "crawler/ranges.h"

#include <algorithm>
#include <array>
#include <asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/network.h"
#include "common/refresher.h"
#include "crawler/crawlers.h"

namespace bot_shield {
namespace {

std::array<uint8_t, 16> Mapped(const asio::ip::address& address) {
  if (address.is_v4()) {
    return asio::ip::make_address_v6(asio::ip::v4_mapped, address.to_v4())
        .to_bytes();
  }
  return address.to_v6().to_bytes();
}

// The address after `address` (wraps at the top, which never matters here).
std::array<uint8_t, 16> Next(std::array<uint8_t, 16> address) {
  for (uint8_t& byte : std::ranges::reverse_view(address)) {
    if (++byte != 0) break;
  }
  return address;
}

}  // namespace

void IpRangeSet::Add(const Network& network) {
  Interval interval{network.bytes, network.bytes};
  for (int bit = network.prefix; bit < 128; ++bit) {
    const auto byte = static_cast<std::size_t>(bit / 8);
    const auto mask = static_cast<uint8_t>(0x80 >> (bit % 8));
    interval.start[byte] = static_cast<uint8_t>(interval.start[byte] & ~mask);
    interval.end[byte] = static_cast<uint8_t>(interval.end[byte] | mask);
  }
  intervals_.push_back(interval);
}

void IpRangeSet::Finish() {
  std::ranges::sort(intervals_, {}, &Interval::start);
  std::vector<Interval> merged;
  for (const Interval& interval : intervals_) {
    if (!merged.empty() && (interval.start <= merged.back().end ||
                            interval.start == Next(merged.back().end))) {
      merged.back().end = std::max(merged.back().end, interval.end);
    } else {
      merged.push_back(interval);
    }
  }
  intervals_ = std::move(merged);
}

IpRangeSet IpRangeSet::Union(const std::vector<const IpRangeSet*>& sets) {
  IpRangeSet out;
  for (const IpRangeSet* set : sets) {
    out.intervals_.insert(out.intervals_.end(), set->intervals_.begin(),
                          set->intervals_.end());
  }
  out.Finish();
  return out;
}

bool IpRangeSet::Contains(const asio::ip::address& address) const {
  const std::array<uint8_t, 16> ip = Mapped(address);
  auto it = std::ranges::upper_bound(intervals_, ip, {}, &Interval::start);
  if (it == intervals_.begin()) return false;
  --it;
  return ip <= it->end;
}

bool ParseCrawlerRanges(std::string_view json, IpRangeSet* set,
                        std::string* error) {
  const nlohmann::json root = nlohmann::json::parse(json, nullptr, false);
  const auto prefixes = root.is_object() ? root.find("prefixes") : root.end();
  if (root.is_discarded() || !root.is_object() || prefixes == root.end() ||
      !prefixes->is_array()) {
    *error = "not a {\"prefixes\": [...]} document";
    return false;
  }
  std::size_t added = 0;
  for (const nlohmann::json& item : *prefixes) {
    if (!item.is_object()) continue;
    for (const char* key : {"ipv4Prefix", "ipv6Prefix"}) {
      const auto value = item.find(key);
      if (value == item.end() || !value->is_string()) continue;
      Network network;
      if (!Network::Parse(value->get<std::string>(), &network)) {
        *error = std::format("bad prefix {}", value->get<std::string>());
        return false;
      }
      set->Add(network);
      ++added;
    }
  }
  if (added == 0) {
    *error = "no prefixes";
    return false;
  }
  return true;
}

void CrawlerRangeStore::Update(std::string_view id, std::string_view url,
                               IpRangeSet ranges) {
  const std::scoped_lock lock(mutex_);
  auto& by_url = sources_[std::string(id)];
  by_url[std::string(url)] = std::move(ranges);
  auto snapshot = std::make_shared<Snapshot>(*snapshot_);
  std::vector<const IpRangeSet*> sets;
  for (const auto& entry : by_url) sets.push_back(&entry.second);
  (*snapshot)[std::string(id)] = IpRangeSet::Union(sets);
  snapshot_ = std::move(snapshot);
}

std::shared_ptr<const CrawlerRangeStore::Snapshot> CrawlerRangeStore::snapshot()
    const {
  const std::scoped_lock lock(mutex_);
  return snapshot_;
}

CrawlerStatus CheckCrawlerRanges(const KnownCrawler& crawler,
                                 const CrawlerRangeStore::Snapshot& ranges,
                                 const asio::ip::address& address) {
  const auto it = ranges.find(crawler.id);
  if (it == ranges.end() || it->second.empty()) return CrawlerStatus::kPending;
  if (it->second.Contains(address)) return CrawlerStatus::kVerified;
  return crawler.domains.empty() ? CrawlerStatus::kFailed
                                 : CrawlerStatus::kPending;
}

std::vector<RefreshSource> CrawlerRangeSources(CrawlerRangeStore* store,
                                               const std::string& data_dir,
                                               std::chrono::seconds refresh) {
  std::vector<RefreshSource> sources;
  for (const KnownCrawler& crawler : KnownCrawlers()) {
    int index = 0;
    for (const std::string_view url : crawler.ranges) {
      RefreshSource source;
      source.name = std::format("crawler ranges {}", crawler.id);
      source.url = std::string(url);
      if (!data_dir.empty()) {
        source.cache_file =
            std::format("{}/crawler-{}-{}.json", data_dir, crawler.id, index);
      }
      source.refresh = refresh;
      source.max_size = std::size_t{4} << 20;
      source.apply = [store, id = std::string(crawler.id),
                      url = std::string(url)](std::string_view data,
                                              std::string* error) {
        IpRangeSet set;
        if (!ParseCrawlerRanges(data, &set, error)) return false;
        set.Finish();
        store->Update(id, url, std::move(set));
        return true;
      };
      sources.push_back(std::move(source));
      ++index;
    }
  }
  return sources;
}

}  // namespace bot_shield
