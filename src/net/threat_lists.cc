#include "net/threat_lists.h"

#include <algorithm>
#include <array>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/network.h"
#include "common/refresher.h"
#include "crawler/ranges.h"

namespace bot_shield {
namespace {

// URLs checked by downloading them (2026-10).
constexpr std::string_view kTorUrls[] = {
    "https://check.torproject.org/torbulkexitlist"};
constexpr std::string_view kFireholUrls[] = {
    "https://iplists.firehol.org/files/firehol_level1.netset"};
constexpr std::string_view kSpamhausUrls[] = {
    "https://www.spamhaus.org/drop/drop_v4.json",
    "https://www.spamhaus.org/drop/drop_v6.json"};

constexpr ThreatList kLists[] = {
    {"tor", kTorUrls, "tor_exit"},
    {"firehol_level1", kFireholUrls, "threat_list"},
    {"spamhaus_drop", kSpamhausUrls, "threat_list"},
};

std::string_view Trim(std::string_view text) {
  const auto first = text.find_first_not_of(" \t\r");
  if (first == std::string_view::npos) return {};
  const auto last = text.find_last_not_of(" \t\r");
  return text.substr(first, last - first + 1);
}

// Non-global IPv4 networks (RFC 6890 and multicast/reserved).
constexpr std::string_view kSpecialV4[] = {
    "0.0.0.0/8",      "10.0.0.0/8",    "100.64.0.0/10",   "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",    "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4",    "240.0.0.0/4"};

}  // namespace

std::span<const ThreatList> KnownThreatLists() { return kLists; }

const ThreatList* FindThreatList(std::string_view id) {
  const auto it = std::ranges::find(kLists, id, &ThreatList::id);
  return it == std::end(kLists) ? nullptr : &*it;
}

bool ParseIpList(std::string_view text, IpRangeSet* set, std::string* error) {
  std::size_t added = 0;
  for (const auto part : std::views::split(text, '\n')) {
    std::string_view line = Trim(std::string_view(part.begin(), part.end()));
    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    std::string cidr;
    if (line[0] == '{') {
      const nlohmann::json item = nlohmann::json::parse(line, nullptr, false);
      if (item.is_discarded() || !item.is_object()) continue;
      const auto it = item.find("cidr");
      if (it == item.end() || !it->is_string()) continue;
      cidr = it->get<std::string>();
    } else {
      cidr = std::string(line.substr(0, line.find_first_of(" \t;#")));
    }
    Network network;
    if (!Network::Parse(cidr, &network)) continue;
    set->Add(network);
    ++added;
  }
  if (added == 0) {
    *error = "no addresses or networks in the list";
    return false;
  }
  return true;
}

bool IsGlobalAddress(const asio::ip::address& address) {
  if (address.is_unspecified() || address.is_loopback() ||
      address.is_multicast()) {
    return false;
  }
  if (address.is_v6()) {
    const asio::ip::address_v6 v6 = address.to_v6();
    if (v6.is_v4_mapped()) {
      return IsGlobalAddress(
          asio::ip::make_address_v4(asio::ip::v4_mapped, v6));
    }
    const std::array<uint8_t, 16> bytes = v6.to_bytes();
    // fc00::/7 unique local, fe80::/10 link-local, 2001:db8::/32 docs.
    if ((bytes[0] & 0xfe) == 0xfc) return false;
    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d &&
        bytes[3] == 0xb8) {
      return false;
    }
    return true;
  }
  for (const std::string_view text : kSpecialV4) {
    Network network;
    if (Network::Parse(text, &network) && network.Contains(address)) {
      return false;
    }
  }
  return true;
}

void ThreatListStore::Update(std::string_view id, std::string_view url,
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

std::shared_ptr<const ThreatListStore::Snapshot> ThreatListStore::snapshot()
    const {
  const std::scoped_lock lock(mutex_);
  return snapshot_;
}

std::vector<std::string> ThreatListStore::Match(
    const Snapshot& lists, const asio::ip::address& address) {
  std::vector<std::string> out;
  if (!IsGlobalAddress(address)) return out;
  for (const auto& [id, ranges] : lists) {
    if (ranges.Contains(address)) out.push_back(id);
  }
  return out;
}

std::vector<RefreshSource> ThreatListSources(
    const std::vector<std::string>& ids, ThreatListStore* store,
    const std::string& data_dir, std::chrono::seconds refresh) {
  std::vector<RefreshSource> sources;
  for (const std::string& id : ids) {
    const ThreatList* list = FindThreatList(id);
    if (list == nullptr) continue;
    int index = 0;
    for (const std::string_view url : list->urls) {
      RefreshSource source;
      source.name = std::format("threat list {}", id);
      source.url = std::string(url);
      if (!data_dir.empty()) {
        source.cache_file =
            std::format("{}/threat-{}-{}.txt", data_dir, id, index);
      }
      source.refresh = refresh;
      source.max_size = std::size_t{16} << 20;
      source.apply = [store, id = std::string(id), url = std::string(url)](
                         std::string_view data, std::string* error) {
        IpRangeSet set;
        if (!ParseIpList(data, &set, error)) return false;
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
