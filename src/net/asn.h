#ifndef BOT_SHIELD_NET_ASN_H_
#define BOT_SHIELD_NET_ASN_H_

#include <array>
#include <asio/ip/address.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {

struct AsnInfo {
  uint32_t asn = 0;
  std::string_view org;      // AS description; valid while the db lives.
  std::string_view country;  // Registration country, ISO code.
  // Cloud, hosting or data centre network (curated ASNs and name hints):
  // real browsers there are mostly VPNs and proxies.
  bool hosting = false;
};

// IP -> AS lookup over iptoasn.com's ip2asn-combined.tsv (IPv4 and IPv6:
// "start<TAB>end<TAB>asn<TAB>country<TAB>description"). Immutable once
// parsed; ~600k ranges take ~25 MB.
class AsnDatabase {
 public:
  static bool Parse(std::string_view tsv, AsnDatabase* out, std::string* error);

  std::optional<AsnInfo> Lookup(const asio::ip::address& address) const;
  std::size_t size() const { return v4_.size() + v6_.size(); }

 private:
  struct As {
    uint32_t asn = 0;
    std::string org;
    std::string country;
    bool hosting = false;
  };
  struct V4Range {
    uint32_t start;
    uint32_t end;
    uint32_t as;  // Index into ases_.
  };
  struct V6Range {
    std::array<uint8_t, 16> start;
    std::array<uint8_t, 16> end;
    uint32_t as;
  };

  AsnInfo Info(uint32_t index) const;

  std::vector<As> ases_;
  std::vector<V4Range> v4_;
  std::vector<V6Range> v6_;
};

// Whether an AS is a hosting network by its number or description.
bool IsHostingAs(uint32_t asn, std::string_view org);

// The current database, replaced by the background refresh. Lookups take
// the snapshot once per request.
class AsnStore {
 public:
  std::shared_ptr<const AsnDatabase> snapshot() const {
    const std::scoped_lock lock(mutex_);
    return database_;
  }
  void set(std::shared_ptr<const AsnDatabase> database) {
    const std::scoped_lock lock(mutex_);
    database_ = std::move(database);
  }

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<const AsnDatabase> database_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_ASN_H_
