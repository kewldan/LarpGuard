#ifndef BOT_SHIELD_CRAWLER_RANGES_H_
#define BOT_SHIELD_CRAWLER_RANGES_H_

#include <array>
#include <asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "common/network.h"
#include "common/refresher.h"
#include "crawler/crawlers.h"

namespace bot_shield {

// A set of networks, merged into sorted intervals for binary search.
class IpRangeSet {
 public:
  void Add(const Network& network);
  // Sorts and merges; call once after the last Add.
  void Finish();
  bool Contains(const asio::ip::address& address) const;
  // Union of finished sets (finished).
  static IpRangeSet Union(const std::vector<const IpRangeSet*>& sets);
  std::size_t size() const { return intervals_.size(); }
  bool empty() const { return intervals_.empty(); }

 private:
  struct Interval {
    std::array<uint8_t, 16> start;
    std::array<uint8_t, 16> end;
  };
  std::vector<Interval> intervals_;
};

// Published crawler ranges in the common JSON layout (Google, Bing,
// OpenAI, Perplexity, Apple, DuckDuckGo, Mistral):
//   {"prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv6Prefix": ...}]}
// Adds them to `set` (not finished).
bool ParseCrawlerRanges(std::string_view json, IpRangeSet* set,
                        std::string* error);

// Range lists of the known crawlers, by crawler id, replaced as sources
// refresh. A crawler's set is the union of all its sources.
class CrawlerRangeStore {
 public:
  using Snapshot = std::map<std::string, IpRangeSet, std::less<>>;

  // Replaces the ranges from `url` (one of crawler `id`'s sources).
  void Update(std::string_view id, std::string_view url, IpRangeSet ranges);
  std::shared_ptr<const Snapshot> snapshot() const;

 private:
  mutable std::mutex mutex_;
  // crawler id -> url -> ranges.
  std::map<std::string, std::map<std::string, IpRangeSet, std::less<>>,
           std::less<>>
      sources_;
  std::shared_ptr<const Snapshot> snapshot_ = std::make_shared<Snapshot>();
};

// What the published ranges say about `crawler` at `address`: kVerified
// inside them; kFailed outside them when the crawler has no reverse DNS
// domains to prove itself otherwise; kPending when the ranges cannot
// decide (none published or not loaded yet).
CrawlerStatus CheckCrawlerRanges(const KnownCrawler& crawler,
                                 const CrawlerRangeStore::Snapshot& ranges,
                                 const asio::ip::address& address);

// Refresh sources for every published range list, feeding `store`. Cached
// as <data_dir>/crawler-<id>-<n>.json when `data_dir` is set.
std::vector<RefreshSource> CrawlerRangeSources(CrawlerRangeStore* store,
                                               const std::string& data_dir,
                                               std::chrono::seconds refresh);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CRAWLER_RANGES_H_
