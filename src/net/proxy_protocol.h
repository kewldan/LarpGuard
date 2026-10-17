#ifndef BOT_SHIELD_NET_PROXY_PROTOCOL_H_
#define BOT_SHIELD_NET_PROXY_PROTOCOL_H_

#include <asio/ip/tcp.hpp>
#include <cstdint>
#include <string_view>
#include <vector>

namespace bot_shield {

// Encodes a PROXY protocol v2 header (PROXY command, TCP) so Traefik sees the
// real client address. IPv4-mapped IPv6 addresses are sent as IPv4. If
// `authority` is not empty it is attached as a PP2_TYPE_AUTHORITY TLV (the
// SNI of the client connection).
std::vector<uint8_t> EncodeProxyV2(const asio::ip::tcp::endpoint& source,
                                   const asio::ip::tcp::endpoint& destination,
                                   std::string_view authority);

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_PROXY_PROTOCOL_H_
