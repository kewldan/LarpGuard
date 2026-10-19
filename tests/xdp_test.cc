#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "common/network.h"
#include "xdp/xdp_filter.h"

namespace bot_shield {
namespace {

constexpr int kDrop = 1;
constexpr int kPass = 2;

std::string U16(uint16_t value) {
  return {static_cast<char>(value >> 8), static_cast<char>(value & 0xFF)};
}

// Ethernet + IPv4 (or IPv6) + TCP (or UDP) with the given flags.
std::string Frame(std::string_view source, uint16_t port, uint8_t tcp_flags,
                  bool udp = false) {
  std::string frame(12, '\x02');  // MAC addresses.
  const asio::ip::address address = asio::ip::make_address(source);
  const char protocol = udp ? 17 : 6;
  if (address.is_v4()) {
    frame += U16(0x0800);
    std::string ip(20, '\0');
    ip[0] = 0x45;
    ip[8] = 64;
    ip[9] = protocol;
    const auto bytes = address.to_v4().to_bytes();
    for (int i = 0; i < 4; ++i) ip[12 + i] = static_cast<char>(bytes[i]);
    ip[16] = 10;  // Destination 10.0.0.1.
    ip[19] = 1;
    frame += ip;
  } else {
    frame += U16(0x86dd);
    std::string ip(40, '\0');
    ip[0] = 0x60;
    ip[6] = protocol;
    ip[7] = 64;
    const auto bytes = address.to_v6().to_bytes();
    for (int i = 0; i < 16; ++i) ip[8 + i] = static_cast<char>(bytes[i]);
    ip[39] = 1;
    frame += ip;
  }
  std::string transport(udp ? 8 : 20, '\0');
  transport.replace(0, 2, U16(40000));
  transport.replace(2, 2, U16(port));
  if (!udp) {
    transport[12] = 0x50;
    transport[13] = static_cast<char>(tcp_flags);
  }
  frame += transport;
  frame += std::string(16, '\0');
  return frame;
}

constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kAck = 0x10;

Network Net(std::string_view text) {
  Network network;
  EXPECT_TRUE(Network::Parse(text, &network));
  return network;
}

std::unique_ptr<XdpFilter> Load(const XdpSettings& settings) {
  std::string error;
  std::unique_ptr<XdpFilter> filter = XdpFilter::LoadForTest(settings, &error);
  return filter;
}

class XdpTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!XdpAvailable()) GTEST_SKIP() << "XDP not in this build";
    settings_.ports = {80, 443};
    filter_ = Load(settings_);
    if (filter_ == nullptr) {
      std::string error;
      XdpFilter::LoadForTest(settings_, &error);
      GTEST_SKIP() << "cannot load BPF here (needs root/CAP_BPF): " << error;
    }
  }

  XdpSettings settings_;
  std::unique_ptr<XdpFilter> filter_;
};

int64_t UnixNow() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

TEST_F(XdpTest, PassesOrdinaryTraffic) {
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, kSyn)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, kAck)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("2001:db8::7", 80, kSyn)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 22, 0)), kPass);
  EXPECT_EQ(filter_->TestRun(std::string(14, '\0')), kPass);
}

TEST_F(XdpTest, DropsBlocklistedSourcesOnProtectedPorts) {
  ASSERT_TRUE(filter_->SyncBlocklist(
      {{Net("203.0.113.0/24"), 0},
       {Net("2001:db8:bad::/48"), 0},
       {Net("192.0.2.1"), UnixNow() - 10}},  // Expired: ignored.
      UnixNow()));
  EXPECT_EQ(filter_->TestRun(Frame("203.0.113.5", 443, kSyn)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("203.0.113.5", 443, kAck)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("203.0.113.5", 22, kSyn)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("203.0.114.5", 443, kSyn)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("2001:db8:bad::1", 443, kSyn)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("2001:db8:bad0::1", 443, kSyn)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("192.0.2.1", 443, kSyn)), kPass);

  // Removed entries stop dropping.
  ASSERT_TRUE(
      filter_->SyncBlocklist({{Net("2001:db8:bad::/48"), 0}}, UnixNow()));
  EXPECT_EQ(filter_->TestRun(Frame("203.0.113.5", 443, kSyn)), kPass);
  EXPECT_EQ(filter_->TestRun(Frame("2001:db8:bad::1", 443, kSyn)), kDrop);
  EXPECT_GE(filter_->Stats().blocked, 4U);

  // A stale heartbeat (stalled gateway) passes everything.
  ASSERT_TRUE(filter_->WriteConfig(false));
  EXPECT_EQ(filter_->TestRun(Frame("2001:db8:bad::1", 443, kSyn)), kPass);
  EXPECT_GE(filter_->Stats().fail_open, 1U);
}

TEST_F(XdpTest, DropsInvalidFlagsAndUnexpectedUdp) {
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, kSyn | 0x01)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, kSyn | 0x04)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, 0)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, 0x29)), kDrop);
  EXPECT_EQ(filter_->TestRun(Frame("198.51.100.7", 443, 0, true)), kDrop);
  EXPECT_GE(filter_->Stats().invalid, 5U);

  XdpSettings quic = settings_;
  quic.allow_udp = true;
  std::unique_ptr<XdpFilter> with_quic = Load(quic);
  ASSERT_NE(with_quic, nullptr);
  EXPECT_EQ(with_quic->TestRun(Frame("198.51.100.7", 443, 0, true)), kPass);
}

TEST_F(XdpTest, LimitsSynsPerPrefix) {
  XdpSettings limited = settings_;
  limited.syn_rate = 1;
  limited.syn_burst = 3;
  std::unique_ptr<XdpFilter> filter = Load(limited);
  ASSERT_NE(filter, nullptr);
  int passed = 0;
  for (int i = 0; i < 10; ++i) {
    // Different hosts of one /24 share the budget.
    passed += filter->TestRun(Frame("198.51.100." + std::to_string(i + 1), 443,
                                    kSyn)) == kPass;
  }
  EXPECT_EQ(passed, 3);
  // Another network has its own; established traffic is never limited.
  EXPECT_EQ(filter->TestRun(Frame("198.51.101.1", 443, kSyn)), kPass);
  EXPECT_EQ(filter->TestRun(Frame("198.51.100.1", 443, kAck)), kPass);
  EXPECT_GE(filter->Stats().syn_rate, 7U);
}

TEST(XdpAutoBlocksTest, ExpireAndBound) {
  XdpAutoBlocks blocks;
  blocks.Add(asio::ip::make_address("::ffff:198.51.100.7"), 1000);
  blocks.Add(asio::ip::make_address("2001:db8::1"), 2000);
  XdpBlocklist list = blocks.Snapshot(500);
  ASSERT_EQ(list.size(), 2U);
  EXPECT_TRUE(list[0].first.v4 || list[1].first.v4);
  EXPECT_EQ(blocks.Snapshot(1500).size(), 1U);
  EXPECT_TRUE(blocks.Snapshot(2500).empty());
}

}  // namespace
}  // namespace bot_shield
