#include "net/geoip.h"

#include <algorithm>
#include <array>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace bot_shield {

bool GeoDatabase::Parse(std::string_view csv, GeoDatabase* out,
                        std::string* error) {
  GeoDatabase db;
  std::size_t lines = 0;
  std::size_t bad = 0;
  while (!csv.empty()) {
    const std::size_t newline = csv.find('\n');
    std::string_view line = csv.substr(0, newline);
    csv.remove_prefix(newline == std::string_view::npos ? csv.size()
                                                        : newline + 1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) continue;
    ++lines;
    const std::size_t first = line.find(',');
    const std::size_t second = line.find(',', first + 1);
    if (first == std::string_view::npos || second == std::string_view::npos ||
        line.size() - second - 1 != 2) {
      ++bad;
      continue;
    }
    const std::string start_text(line.substr(0, first));
    const std::string end_text(line.substr(first + 1, second - first - 1));
    std::array<char, 2> country = {line[second + 1], line[second + 2]};
    // "ZZ": unassigned or reserved.
    if (country == std::array<char, 2>{'Z', 'Z'}) country = {'\0', '\0'};
    std::error_code start_error;
    std::error_code end_error;
    const asio::ip::address start =
        asio::ip::make_address(start_text, start_error);
    const asio::ip::address end = asio::ip::make_address(end_text, end_error);
    if (start_error || end_error || start.is_v4() != end.is_v4()) {
      ++bad;
      continue;
    }
    if (start.is_v4()) {
      V4Range range{start.to_v4().to_uint(), end.to_v4().to_uint(), country};
      if (range.end < range.start) {
        ++bad;
        continue;
      }
      db.v4_.push_back(range);
    } else {
      V6Range range{start.to_v6().to_bytes(), end.to_v6().to_bytes(), country};
      if (range.end < range.start) {
        ++bad;
        continue;
      }
      db.v6_.push_back(range);
    }
  }
  if (db.v4_.empty() && db.v6_.empty()) {
    *error = std::format("geoip: no ranges in {} lines", lines);
    return false;
  }
  if (bad * 100 > lines) {
    *error = std::format("geoip: {} of {} lines unreadable", bad, lines);
    return false;
  }
  std::ranges::sort(db.v4_, {}, &V4Range::start);
  std::ranges::sort(db.v6_, {}, &V6Range::start);
  *out = std::move(db);
  return true;
}

std::string_view GeoDatabase::Lookup(const asio::ip::address& address) const {
  const auto code = [](const std::array<char, 2>& country) {
    return country[0] == '\0' ? std::string_view()
                              : std::string_view(country.data(), 2);
  };
  if (address.is_v4() || (address.is_v6() && address.to_v6().is_v4_mapped())) {
    const uint32_t ip =
        address.is_v4()
            ? address.to_v4().to_uint()
            : asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6())
                  .to_uint();
    auto it = std::ranges::upper_bound(v4_, ip, {}, &V4Range::start);
    if (it == v4_.begin()) return {};
    --it;
    return ip > it->end ? std::string_view() : code(it->country);
  }
  const std::array<uint8_t, 16> ip = address.to_v6().to_bytes();
  auto it = std::ranges::upper_bound(v6_, ip, {}, &V6Range::start);
  if (it == v6_.begin()) return {};
  --it;
  return ip > it->end ? std::string_view() : code(it->country);
}

std::vector<std::string> GeoUrlsToTry(std::string_view url,
                                      std::chrono::sys_days today) {
  if (url.find("{month}") == std::string_view::npos) return {std::string(url)};
  const std::chrono::year_month_day day{today};
  std::vector<std::string> urls;
  for (const std::chrono::year_month month :
       {day.year() / day.month(),
        day.year() / day.month() - std::chrono::months(1)}) {
    urls.push_back(
        GeoUrlForMonth(url, static_cast<int>(month.year()),
                       static_cast<int>(static_cast<unsigned>(month.month()))));
  }
  return urls;
}

std::string GeoUrlForMonth(std::string_view url, int year, int month) {
  std::string out(url);
  constexpr std::string_view kPlaceholder = "{month}";
  const std::string value = std::format("{:04}-{:02}", year, month);
  for (std::size_t at = out.find(kPlaceholder); at != std::string::npos;
       at = out.find(kPlaceholder, at + value.size())) {
    out.replace(at, kPlaceholder.size(), value);
  }
  return out;
}

}  // namespace bot_shield
