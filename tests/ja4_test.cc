#include "fp/ja4.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "test_util.h"
#include "tls/client_hello.h"

namespace bot_shield {
namespace {

// The ClientHello behind the example in FoxIO's JA4 README:
// t13d1516h2_8daaf6152771_e5627efa2ab1 (Chrome).
ClientHello ChromeHello() {
  ClientHello hello;
  hello.legacy_version = 0x0303;
  hello.server_name = "example.com";
  hello.alpn = {"h2", "http/1.1"};
  hello.cipher_suites = {0x5A5A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F,
                         0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
                         0x009C, 0x009D, 0x002F, 0x0035};
  hello.extensions = {0x2A2A, 0x0000, 0x0017, 0xFF01, 0x000A, 0x000B,
                      0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033,
                      0x002D, 0x002B, 0x001B, 0x4469, 0x0015, 0x3A3A};
  hello.signature_algorithms = {0x0403, 0x0804, 0x0401, 0x0503,
                                0x0805, 0x0501, 0x0806, 0x0601};
  hello.supported_versions = {0x7A7A, 0x0304, 0x0303};
  return hello;
}

TEST(Ja4Test, MatchesFoxIoExample) {
  EXPECT_EQ(Ja4(ChromeHello()), "t13d1516h2_8daaf6152771_e5627efa2ab1");
}

TEST(Ja4Test, RawVariantKeepsSortedLists) {
  EXPECT_EQ(Ja4Raw(ChromeHello()),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,"
            "c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,"
            "001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,"
            "0501,0806,0601");
}

TEST(Ja4Test, NoServerNameNoAlpnNoExtensions) {
  ClientHello hello;
  hello.legacy_version = 0x0303;
  hello.cipher_suites = {0x002F};
  // sha256("002f") starts with ba72b8082249.
  EXPECT_EQ(Ja4(hello), "t12i010000_ba72b8082249_000000000000");
}

TEST(Ja4Test, AlpnWithNonAlphanumericEnds) {
  ClientHello hello = ChromeHello();
  hello.alpn = {"h2;"};
  // Hex of "h2;" is 68323b: first and last hex characters.
  EXPECT_EQ(Ja4(hello).substr(8, 2), "6b");
  hello.alpn = {"http/1.1"};
  EXPECT_EQ(Ja4(hello).substr(8, 2), "h1");
}

TEST(Ja4Test, Grease) {
  EXPECT_TRUE(IsGrease(0x0A0A));
  EXPECT_TRUE(IsGrease(0xFAFA));
  EXPECT_FALSE(IsGrease(0x0A1A));
  EXPECT_FALSE(IsGrease(0x1301));
}

TEST(Ja4Test, WorksOnParsedHello) {
  const auto bytes = testing::MakeClientHello("a.test", {"h2", "http/1.1"});
  ClientHello hello;
  ASSERT_EQ(ParseClientHello(bytes, &hello), ParseStatus::kOk);
  const std::string ja4 = Ja4(hello);
  EXPECT_TRUE(ja4.starts_with("t13d")) << ja4;
  EXPECT_EQ(ja4.substr(8, 2), "h2");
  EXPECT_EQ(ja4.size(), 36u);
}

}  // namespace
}  // namespace bot_shield
