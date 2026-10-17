#include "fp/tcp_syn.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#if BOT_SHIELD_FOXIO
#include "fp/foxio/ja4plus.h"
#endif

namespace bot_shield {
namespace {

// TCP header (20 bytes + options) for a SYN with the given window and options.
std::vector<uint8_t> TcpHeader(uint16_t window,
                               const std::vector<uint8_t>& options,
                               uint8_t flags = 0x02) {
  std::vector<uint8_t> tcp = {0xC3, 0x50, 0x01, 0xBB,  // ports
                              0,    0,    0,    1,     // seq
                              0,    0,    0,    0};    // ack
  const auto header_words = static_cast<uint8_t>((20 + options.size()) / 4);
  tcp.push_back(static_cast<uint8_t>(header_words << 4));
  tcp.push_back(flags);
  tcp.push_back(static_cast<uint8_t>(window >> 8));
  tcp.push_back(static_cast<uint8_t>(window & 0xFF));
  tcp.insert(tcp.end(), {0, 0, 0, 0});  // checksum, urgent pointer
  tcp.insert(tcp.end(), options.begin(), options.end());
  return tcp;
}

std::vector<uint8_t> Ipv4(uint8_t ttl, bool dont_fragment,
                          const std::vector<uint8_t>& tcp) {
  std::vector<uint8_t> packet = {
      0x45, 0,   0,  0, 0, 0,   static_cast<uint8_t>(dont_fragment ? 0x40 : 0),
      0,    ttl, 6,  0, 0, 203, 0,
      113,  7,   10, 0, 0, 1};
  packet.insert(packet.end(), tcp.begin(), tcp.end());
  return packet;
}

// Linux-style options: MSS 1460, SACK permitted, timestamps, NOP, wscale 7.
std::vector<uint8_t> LinuxOptions() {
  return {2, 4,  0x05, 0xB4,                    // MSS 1460
          4, 2,                                 // SACK permitted
          8, 10, 0,    0,    0, 1, 0, 0, 0, 0,  // timestamps
          1,                                    // NOP
          3, 3,  7};                            // window scale 7
}  // window scale 7

TEST(TcpSynTest, ParsesIpv4Syn) {
  TcpSyn syn;
  ASSERT_TRUE(
      ParseTcpSyn(Ipv4(61, true, TcpHeader(64240, LinuxOptions())), &syn));
  EXPECT_EQ(syn.ip_version, 4);
  EXPECT_EQ(syn.ttl, 61);
  EXPECT_TRUE(syn.dont_fragment);
  EXPECT_EQ(syn.window, 64240);
  EXPECT_EQ(syn.mss, 1460);
  EXPECT_EQ(syn.window_scale, 7);
  EXPECT_FALSE(syn.ecn);
  EXPECT_EQ(syn.options, (std::vector<uint8_t>{2, 4, 8, 1, 3}));
  EXPECT_EQ(TcpFingerprint(syn), "4:64:64240:1460:7:MSTNW:df");
}

TEST(TcpSynTest, ParsesIpv6SynWithEcn) {
  std::vector<uint8_t> packet(40, 0);
  packet[0] = 0x60;
  packet[6] = 6;    // next header: TCP
  packet[7] = 117;  // hop limit
  const auto tcp =
      TcpHeader(65535, {2, 4, 0x05, 0xA0, 1, 1, 4, 2}, 0x02 | 0x40 | 0x80);
  packet.insert(packet.end(), tcp.begin(), tcp.end());

  TcpSyn syn;
  ASSERT_TRUE(ParseTcpSyn(packet, &syn));
  EXPECT_EQ(syn.ip_version, 6);
  EXPECT_TRUE(syn.ecn);
  EXPECT_EQ(syn.window_scale, -1);
  EXPECT_EQ(TcpFingerprint(syn), "6:128:65535:1440:-1:MNNS:ecn");
}

TEST(TcpSynTest, RejectsMalformedPackets) {
  TcpSyn syn;
  EXPECT_FALSE(ParseTcpSyn({}, &syn));
  auto packet = Ipv4(64, false, TcpHeader(1024, LinuxOptions()));
  packet.resize(30);
  EXPECT_FALSE(ParseTcpSyn(packet, &syn));
  // Option claiming more bytes than the header has.
  EXPECT_FALSE(
      ParseTcpSyn(Ipv4(64, false, TcpHeader(1024, {2, 8, 0, 0})), &syn));
  auto udp = Ipv4(64, false, TcpHeader(1024, {}));
  udp[9] = 17;
  EXPECT_FALSE(ParseTcpSyn(udp, &syn));
}

TEST(TcpSynTest, InitialTtl) {
  EXPECT_EQ(InitialTtl(30), 32);
  EXPECT_EQ(InitialTtl(52), 64);
  EXPECT_EQ(InitialTtl(64), 64);
  EXPECT_EQ(InitialTtl(113), 128);
  EXPECT_EQ(InitialTtl(240), 255);
}

#if BOT_SHIELD_FOXIO
TEST(TcpSynTest, Ja4t) {
  TcpSyn syn;
  ASSERT_TRUE(
      ParseTcpSyn(Ipv4(64, true, TcpHeader(64240, LinuxOptions())), &syn));
  EXPECT_EQ(foxio::Ja4t(syn), "64240_2-4-8-1-3_1460_7");
  TcpSyn bare;
  bare.window = 1024;
  EXPECT_EQ(foxio::Ja4t(bare), "1024_00_00_00");
}
#endif

}  // namespace
}  // namespace bot_shield
