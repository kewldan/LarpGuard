#include "common/host.h"

#include <gtest/gtest.h>

namespace bot_shield {
namespace {

TEST(HostTest, Normalizes) {
  EXPECT_EQ(NormalizeHost("Example.COM."), "example.com");
  EXPECT_EQ(NormalizeHost("a.b"), "a.b");
}

TEST(HostTest, ParentDomain) {
  EXPECT_EQ(ParentDomain("a.example.com"), "example.com");
  EXPECT_EQ(ParentDomain("localhost"), "");
}

TEST(HostTest, ValidatesNames) {
  EXPECT_TRUE(IsValidHostName("a-b_c.example.com"));
  EXPECT_FALSE(IsValidHostName(""));
  EXPECT_FALSE(IsValidHostName("a..b"));
  EXPECT_FALSE(IsValidHostName(".a"));
  EXPECT_FALSE(IsValidHostName("a."));
  EXPECT_FALSE(IsValidHostName("a b"));
  EXPECT_FALSE(IsValidHostName(std::string("a\0b", 3)));
  EXPECT_FALSE(IsValidHostName(std::string(254, 'a')));
}

TEST(HostTest, MatchesPatterns) {
  EXPECT_TRUE(HostMatches("a.test", "a.test"));
  EXPECT_FALSE(HostMatches("a.test", "b.test"));
  EXPECT_TRUE(HostMatches("*.test", "a.test"));
  EXPECT_FALSE(HostMatches("*.test", "test"));
  EXPECT_FALSE(HostMatches("*.test", "a.b.test"));
}

}  // namespace
}  // namespace bot_shield
