#ifndef BOT_SHIELD_COMMON_NETWORK_H_
#define BOT_SHIELD_COMMON_NETWORK_H_

#include <array>
#include <asio/ip/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace bot_shield {

// An IPv4 or IPv6 network ("203.0.113.0/24", "2001:db8::/32" or a single
// address). IPv4 is kept in IPv4-mapped IPv6 form so both families compare
// the same way.
struct Network {
  // Parses CIDR notation or a bare address (a /32 or /128).
  static bool Parse(std::string_view text, Network* network);

  bool Contains(const asio::ip::address& address) const;
  std::string ToString() const;

  std::array<uint8_t, 16> bytes{};
  int prefix = 0;  // In the IPv6 form (IPv4 /24 is 120).
  bool v4 = false;
};

// IPv4-mapped IPv6 addresses as plain IPv4.
asio::ip::address Unmapped(const asio::ip::address& address);

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_NETWORK_H_
