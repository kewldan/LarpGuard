#include "net/proxy_protocol.h"

#include <algorithm>
#include <array>

namespace bot_shield {
namespace {

constexpr std::array<uint8_t, 12> kSignature = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
constexpr uint8_t kVersion2Proxy = 0x21;
constexpr uint8_t kTcpOverIpv4 = 0x11;
constexpr uint8_t kTcpOverIpv6 = 0x21;
constexpr uint8_t kTlvAuthority = 0x02;
constexpr std::size_t kMaxAuthority = 255;

asio::ip::address Unmap(const asio::ip::address& address) {
  if (address.is_v6() && address.to_v6().is_v4_mapped()) {
    return asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
  }
  return address;
}

asio::ip::address_v6 ToV6(const asio::ip::address& address) {
  if (address.is_v4()) {
    return asio::ip::make_address_v6(asio::ip::v4_mapped, address.to_v4());
  }
  return address.to_v6();
}

void AppendU16(std::vector<uint8_t>* out, uint16_t value) {
  out->push_back(static_cast<uint8_t>(value >> 8));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

template <typename Bytes>
void AppendBytes(std::vector<uint8_t>* out, const Bytes& bytes) {
  out->insert(out->end(), bytes.begin(), bytes.end());
}

}  // namespace

std::vector<uint8_t> EncodeProxyV2(const asio::ip::tcp::endpoint& source,
                                   const asio::ip::tcp::endpoint& destination,
                                   std::string_view authority) {
  const asio::ip::address src = Unmap(source.address());
  const asio::ip::address dst = Unmap(destination.address());
  const bool ipv4 = src.is_v4() && dst.is_v4();
  authority = authority.substr(0, std::min(authority.size(), kMaxAuthority));

  std::vector<uint8_t> addresses;
  if (ipv4) {
    AppendBytes(&addresses, src.to_v4().to_bytes());
    AppendBytes(&addresses, dst.to_v4().to_bytes());
  } else {
    AppendBytes(&addresses, ToV6(src).to_bytes());
    AppendBytes(&addresses, ToV6(dst).to_bytes());
  }
  AppendU16(&addresses, source.port());
  AppendU16(&addresses, destination.port());
  if (!authority.empty()) {
    addresses.push_back(kTlvAuthority);
    AppendU16(&addresses, static_cast<uint16_t>(authority.size()));
    AppendBytes(&addresses, authority);
  }

  std::vector<uint8_t> header;
  header.reserve(kSignature.size() + 4 + addresses.size());
  AppendBytes(&header, kSignature);
  header.push_back(kVersion2Proxy);
  header.push_back(ipv4 ? kTcpOverIpv4 : kTcpOverIpv6);
  AppendU16(&header, static_cast<uint16_t>(addresses.size()));
  AppendBytes(&header, addresses);
  return header;
}

}  // namespace bot_shield
