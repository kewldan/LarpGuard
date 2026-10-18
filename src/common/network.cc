#include "common/network.h"

#include <array>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <system_error>

namespace bot_shield {

asio::ip::address Unmapped(const asio::ip::address& address) {
  if (address.is_v6() && address.to_v6().is_v4_mapped()) {
    return asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
  }
  return address;
}

bool Network::Parse(std::string_view text, Network* network) {
  std::string_view address_text = text;
  int prefix = -1;
  if (const auto slash = text.find('/'); slash != std::string_view::npos) {
    address_text = text.substr(0, slash);
    const std::string_view bits = text.substr(slash + 1);
    const auto [ptr, ec] =
        std::from_chars(bits.data(), bits.data() + bits.size(), prefix);
    if (ec != std::errc() || ptr != bits.data() + bits.size() || prefix < 0) {
      return false;
    }
  }
  std::error_code ec;
  const asio::ip::address address =
      Unmapped(asio::ip::make_address(std::string(address_text), ec));
  if (ec) return false;
  Network out;
  if (address.is_v4()) {
    if (prefix < 0) prefix = 32;
    if (prefix > 32) return false;
    out.v4 = true;
    out.prefix = prefix + 96;
    out.bytes = asio::ip::make_address_v6(asio::ip::v4_mapped, address.to_v4())
                    .to_bytes();
  } else {
    if (prefix < 0) prefix = 128;
    if (prefix > 128) return false;
    out.prefix = prefix;
    out.bytes = address.to_v6().to_bytes();
  }
  // Clear host bits so ToString() shows the network.
  int bits = out.prefix;
  for (uint8_t& byte : out.bytes) {
    if (bits >= 8) {
      bits -= 8;
      continue;
    }
    byte = static_cast<uint8_t>(byte & ((0xFF << (8 - bits)) & 0xFF));
    bits = 0;
  }
  *network = out;
  return true;
}

bool Network::Contains(const asio::ip::address& address) const {
  const asio::ip::address plain = Unmapped(address);
  std::array<uint8_t, 16> candidate{};
  if (plain.is_v4()) {
    candidate = asio::ip::make_address_v6(asio::ip::v4_mapped, plain.to_v4())
                    .to_bytes();
  } else if (plain.is_v6()) {
    if (v4) return false;
    candidate = plain.to_v6().to_bytes();
  } else {
    return false;
  }
  int bits = prefix;
  for (std::size_t i = 0; i < candidate.size() && bits > 0; ++i, bits -= 8) {
    const auto mask =
        static_cast<uint8_t>(bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF);
    if ((candidate[i] & mask) != (bytes[i] & mask)) return false;
  }
  return true;
}

std::string Network::ToString() const {
  const asio::ip::address_v6 address(bytes);
  if (v4) {
    return std::format(
        "{}/{}",
        asio::ip::make_address_v4(asio::ip::v4_mapped, address).to_string(),
        prefix - 96);
  }
  return std::format("{}/{}", address.to_string(), prefix);
}

}  // namespace bot_shield
