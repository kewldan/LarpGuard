#include "tls/client_hello.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "test_util.h"

namespace bot_shield {
namespace {

using ::bot_shield::testing::MakeClientHello;

std::vector<uint8_t> Bytes(std::string_view text) {
  return {text.begin(), text.end()};
}

// Re-encodes the handshake message of a single-record ClientHello as two
// records split at `split` bytes into the handshake body.
std::vector<uint8_t> SplitIntoTwoRecords(const std::vector<uint8_t>& hello,
                                         size_t split) {
  const std::span<const uint8_t> message = std::span(hello).subspan(5);
  std::vector<uint8_t> out;
  auto append_record = [&](size_t begin, size_t end) {
    const size_t size = end - begin;
    out.insert(out.end(), {22, 3, 1, static_cast<uint8_t>(size >> 8),
                           static_cast<uint8_t>(size & 0xFF)});
    const auto fragment = message.subspan(begin, end - begin);
    out.insert(out.end(), fragment.begin(), fragment.end());
  };
  append_record(0, split);
  append_record(split, message.size());
  return out;
}

TEST(ClientHelloTest, ParsesServerNameAndAlpn) {
  const auto bytes = MakeClientHello("Example.COM", {"h2", "http/1.1"});
  ClientHello hello;
  ASSERT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kOk);
  EXPECT_EQ(hello.server_name, "example.com");
  EXPECT_EQ(hello.alpn, (std::vector<std::string>{"h2", "http/1.1"}));
  EXPECT_TRUE(hello.HasAlpn("h2"));
  EXPECT_FALSE(hello.HasAlpn("acme-tls/1"));
  EXPECT_FALSE(hello.cipher_suites.empty());
  EXPECT_FALSE(hello.extensions.empty());
  EXPECT_FALSE(hello.supported_groups.empty());
  EXPECT_FALSE(hello.signature_algorithms.empty());
  EXPECT_FALSE(hello.supported_versions.empty());
}

TEST(ClientHelloTest, WithoutServerNameOrAlpn) {
  const auto bytes = MakeClientHello("", {});
  ClientHello hello;
  ASSERT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kOk);
  EXPECT_TRUE(hello.server_name.empty());
  EXPECT_TRUE(hello.alpn.empty());
}

TEST(ClientHelloTest, EveryPrefixNeedsMore) {
  const auto bytes = MakeClientHello("example.com", {"h2"});
  ClientHello hello;
  for (size_t size = 1; size < bytes.size(); ++size) {
    ASSERT_EQ(ParseClientHello(std::span(bytes).first(size), &hello),
              ParseStatus::kNeedMore)
        << "prefix of " << size << " bytes";
  }
  EXPECT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kOk);
}

TEST(ClientHelloTest, ReassemblesAcrossRecords) {
  const auto single = MakeClientHello("split.example.com", {"http/1.1"});
  for (size_t split : {1u, 3u, 4u, 50u}) {
    const auto split_bytes = SplitIntoTwoRecords(single, split);
    ClientHello hello;
    ASSERT_EQ(ParseClientHello(split_bytes, &hello), ParseStatus::kOk)
        << "split at " << split;
    EXPECT_EQ(hello.server_name, "split.example.com");
  }
}

TEST(ClientHelloTest, NotTls) {
  ClientHello hello;
  EXPECT_EQ(ParseClientHello(Bytes("GET / HTTP/1.1\r\n"), &hello),
            ParseStatus::kNotTls);
  EXPECT_EQ(ParseClientHello(std::vector<uint8_t>{0x16, 0x02}, &hello),
            ParseStatus::kNotTls);
}

TEST(ClientHelloTest, EmptyNeedsMore) {
  ClientHello hello;
  EXPECT_EQ(ParseClientHello({}, &hello), ParseStatus::kNeedMore);
}

TEST(ClientHelloTest, RejectsNonClientHelloHandshake) {
  // ServerHello (type 2) in a handshake record.
  const std::vector<uint8_t> bytes = {22, 3, 3, 0, 4, 2, 0, 0, 0};
  ClientHello hello;
  EXPECT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kInvalid);
}

TEST(ClientHelloTest, RejectsCorruptedBody) {
  auto bytes = MakeClientHello("example.com", {"h2"});
  // Drop the last 40 bytes and fix up both length fields, so the record is
  // well-formed but the extensions block claims more data than present.
  constexpr size_t kCut = 40;
  const size_t record_size = ((size_t{bytes[3]} << 8) | bytes[4]) - kCut;
  const size_t message_size =
      ((size_t{bytes[6]} << 16) | (size_t{bytes[7]} << 8) | bytes[8]) - kCut;
  bytes[3] = static_cast<uint8_t>(record_size >> 8);
  bytes[4] = static_cast<uint8_t>(record_size & 0xFF);
  bytes[6] = static_cast<uint8_t>(message_size >> 16);
  bytes[7] = static_cast<uint8_t>((message_size >> 8) & 0xFF);
  bytes[8] = static_cast<uint8_t>(message_size & 0xFF);
  bytes.resize(bytes.size() - kCut);
  ClientHello hello;
  EXPECT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kInvalid);
}

TEST(ClientHelloTest, RejectsOversizedRecord) {
  const std::vector<uint8_t> bytes = {22, 3, 1, 0x50, 0x00};
  ClientHello hello;
  EXPECT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kInvalid);
}

}  // namespace
}  // namespace bot_shield
