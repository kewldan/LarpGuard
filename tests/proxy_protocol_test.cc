#include "net/proxy_protocol.h"

#include <gtest/gtest.h>

#include <array>
#include <span>
#include <vector>

namespace bot_shield {
namespace {

using asio::ip::make_address;
using asio::ip::tcp;

constexpr std::array<uint8_t, 12> kSignature = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

std::vector<uint8_t> Slice(const std::vector<uint8_t>& data, size_t begin,
                           size_t size) {
  const auto bytes = std::span(data).subspan(begin, size);
  return {bytes.begin(), bytes.end()};
}

TEST(ProxyProtocolTest, EncodesIpv4) {
  const auto header =
      EncodeProxyV2(tcp::endpoint(make_address("203.0.113.7"), 51234),
                    tcp::endpoint(make_address("10.0.0.1"), 443), "");
  ASSERT_EQ(header.size(), 16u + 12u);
  EXPECT_EQ(Slice(header, 0, 12),
            std::vector<uint8_t>(kSignature.begin(), kSignature.end()));
  EXPECT_EQ(header[12], 0x21);  // v2, PROXY
  EXPECT_EQ(header[13], 0x11);  // TCP over IPv4
  EXPECT_EQ(header[14], 0);
  EXPECT_EQ(header[15], 12);
  EXPECT_EQ(Slice(header, 16, 4), (std::vector<uint8_t>{203, 0, 113, 7}));
  EXPECT_EQ(Slice(header, 20, 4), (std::vector<uint8_t>{10, 0, 0, 1}));
  EXPECT_EQ(Slice(header, 24, 2), (std::vector<uint8_t>{0xC8, 0x22}));
  EXPECT_EQ(Slice(header, 26, 2), (std::vector<uint8_t>{0x01, 0xBB}));
}

TEST(ProxyProtocolTest, EncodesIpv6) {
  const auto header =
      EncodeProxyV2(tcp::endpoint(make_address("2001:db8::1"), 1000),
                    tcp::endpoint(make_address("2001:db8::2"), 443), "");
  ASSERT_EQ(header.size(), 16u + 36u);
  EXPECT_EQ(header[13], 0x21);  // TCP over IPv6
  EXPECT_EQ(header[15], 36);
  EXPECT_EQ(header[16], 0x20);
  EXPECT_EQ(header[31], 0x01);
}

TEST(ProxyProtocolTest, UnmapsIpv4MappedAddresses) {
  const auto header =
      EncodeProxyV2(tcp::endpoint(make_address("::ffff:198.51.100.9"), 1),
                    tcp::endpoint(make_address("::ffff:10.0.0.1"), 443), "");
  EXPECT_EQ(header[13], 0x11);
  EXPECT_EQ(Slice(header, 16, 4), (std::vector<uint8_t>{198, 51, 100, 9}));
}

TEST(ProxyProtocolTest, MixedFamiliesUseIpv6) {
  const auto header =
      EncodeProxyV2(tcp::endpoint(make_address("2001:db8::1"), 1),
                    tcp::endpoint(make_address("10.0.0.1"), 443), "");
  EXPECT_EQ(header[13], 0x21);
}

TEST(ProxyProtocolTest, AppendsAuthorityTlv) {
  const auto header =
      EncodeProxyV2(tcp::endpoint(make_address("127.0.0.1"), 1),
                    tcp::endpoint(make_address("127.0.0.1"), 2), "a.test");
  ASSERT_EQ(header.size(), 16u + 12u + 3u + 6u);
  EXPECT_EQ(header[15], 12 + 3 + 6);
  EXPECT_EQ(header[28], 0x02);
  EXPECT_EQ(header[29], 0);
  EXPECT_EQ(header[30], 6);
  EXPECT_EQ(std::string(header.begin() + 31, header.end()), "a.test");
}

}  // namespace
}  // namespace bot_shield
