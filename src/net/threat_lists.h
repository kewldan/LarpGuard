#ifndef BOT_SHIELD_NET_THREAT_LISTS_H_
#define BOT_SHIELD_NET_THREAT_LISTS_H_

#include <asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/refresher.h"
#include "crawler/ranges.h"

namespace bot_shield {

// A public IP reputation list the gateway knows (threat_lists.enabled).
struct ThreatList {
  std::string_view id;
  // Plain lists (one address or CIDR per line) or JSON lines ({"cidr"}).
  std::span<const std::string_view> urls;
  // Library signal a listed client gets (weight in fingerprints.yaml).
  std::string_view signal;
};

std::span<const ThreatList> KnownThreatLists();
const ThreatList* FindThreatList(std::string_view id);

// Adds the networks of a list to `set` (not finished): one address or
// CIDR per line, "#" and ";" comments, anything after the first token
// ignored, or JSON lines with a "cidr" field (Spamhaus DROP). False when
// nothing parsed (an error page instead of a list keeps the old copy).
bool ParseIpList(std::string_view text, IpRangeSet* set, std::string* error);

// Not private, loopback, link-local, CGNAT, unique-local, multicast or
// reserved. Lists like FireHOL level1 include such "bogons"; a gateway
// behind NAT or serving a LAN must not flag its own clients.
bool IsGlobalAddress(const asio::ip::address& address);

// The loaded lists by id, replaced as sources refresh; a list's set is the
// union of its URLs.
class ThreatListStore {
 public:
  using Snapshot = std::map<std::string, IpRangeSet, std::less<>>;

  void Update(std::string_view id, std::string_view url, IpRangeSet ranges);
  std::shared_ptr<const Snapshot> snapshot() const;

  // Ids of the lists holding `address`; never a non-global address.
  static std::vector<std::string> Match(const Snapshot& lists,
                                        const asio::ip::address& address);

 private:
  mutable std::mutex mutex_;
  std::map<std::string, std::map<std::string, IpRangeSet, std::less<>>,
           std::less<>>
      sources_;
  std::shared_ptr<const Snapshot> snapshot_ = std::make_shared<Snapshot>();
};

// Refresh sources for the enabled lists, feeding `store`. Cached as
// <data_dir>/threat-<id>-<n>.txt when `data_dir` is set.
std::vector<RefreshSource> ThreatListSources(
    const std::vector<std::string>& ids, ThreatListStore* store,
    const std::string& data_dir, std::chrono::seconds refresh);

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_THREAT_LISTS_H_
