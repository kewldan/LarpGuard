#ifndef BOT_SHIELD_NET_GEOIP_H_
#define BOT_SHIELD_NET_GEOIP_H_

#include <array>
#include <asio/ip/address.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield {

// IP -> country over DB-IP's IP to Country Lite (CC BY 4.0), CSV lines
// "start,end,CC" for IPv4 and IPv6. Immutable once parsed; ~700k ranges
// take ~20 MB.
class GeoDatabase {
 public:
  static bool Parse(std::string_view csv, GeoDatabase* out, std::string* error);

  // ISO 3166-1 alpha-2 code, or "" when unknown ("ZZ" in the data).
  std::string_view Lookup(const asio::ip::address& address) const;
  std::size_t size() const { return v4_.size() + v6_.size(); }

 private:
  struct V4Range {
    uint32_t start;
    uint32_t end;
    std::array<char, 2> country;
  };
  struct V6Range {
    std::array<uint8_t, 16> start;
    std::array<uint8_t, 16> end;
    std::array<char, 2> country;
  };

  std::vector<V4Range> v4_;
  std::vector<V6Range> v6_;
};

// The database URL for a month: "{month}" in `url` becomes "2026-10".
std::string GeoUrlForMonth(std::string_view url, int year, int month);

// The URLs to try in a month (1-12): this month's file, then last month's
// (a new month's file appears a few days in); just `url` without
// "{month}".
std::vector<std::string> GeoUrlsToTry(std::string_view url, int year,
                                      int month);
// Year and month (1-12) of a day counted from 1970-01-01 (UTC).
void YearMonthOfUnixDay(int64_t day, int* year, int* month);

// The current database, replaced by the background refresh; looked up once
// per connection.
class GeoStore {
 public:
  std::shared_ptr<const GeoDatabase> snapshot() const {
    const std::scoped_lock lock(mutex_);
    return database_;
  }
  void set(std::shared_ptr<const GeoDatabase> database) {
    const std::scoped_lock lock(mutex_);
    database_ = std::move(database);
  }

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<const GeoDatabase> database_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_GEOIP_H_
