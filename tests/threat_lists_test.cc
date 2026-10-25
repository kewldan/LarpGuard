#include "net/threat_lists.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <chrono>
#include <string>
#include <utility>
#include <vector>

#include "config/config.h"
#include "crawler/ranges.h"

namespace bot_shield {
namespace {

asio::ip::address Ip(const char* text) { return asio::ip::make_address(text); }

TEST(ThreatListsTest, ParsesPlainAndJsonLines) {
  IpRangeSet set;
  std::string error;
  ASSERT_TRUE(
      ParseIpList("# comment\n"
                  "; another\n"
                  "185.220.101.1\n"
                  "  45.0.0.0/8 ; SBL123\n"
                  "not-an-address\n"
                  "{\"cidr\":\"2a0e:1c80::/29\",\"sblid\":\"SBL1\"}\n"
                  "{\"sblid\":\"no cidr\"}\n",
                  &set, &error))
      << error;
  set.Finish();
  EXPECT_TRUE(set.Contains(Ip("185.220.101.1")));
  EXPECT_FALSE(set.Contains(Ip("185.220.101.2")));
  EXPECT_TRUE(set.Contains(Ip("45.9.9.9")));
  EXPECT_TRUE(set.Contains(Ip("2a0e:1c80::1")));
  // An error page instead of a list keeps the old copy.
  IpRangeSet empty;
  EXPECT_FALSE(ParseIpList("<html>blocked</html>\n", &empty, &error));
}

TEST(ThreatListsTest, OnlyGlobalAddressesMatch) {
  for (const char* local :
       {"10.1.2.3", "127.0.0.1", "192.168.1.1", "172.20.0.1", "100.64.0.1",
        "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "fd00::1", "fe80::1",
        "::ffff:10.0.0.1", "::ffff:127.0.0.1"}) {
    EXPECT_FALSE(IsGlobalAddress(Ip(local))) << local;
  }
  for (const char* global :
       {"8.8.8.8", "185.220.101.1", "::ffff:8.8.8.8", "2a00:1450:4001::1"}) {
    EXPECT_TRUE(IsGlobalAddress(Ip(global))) << global;
  }

  // FireHOL level1 lists bogons like 10.0.0.0/8: a LAN client never matches.
  ThreatListStore store;
  IpRangeSet bogons;
  std::string error;
  ASSERT_TRUE(ParseIpList("10.0.0.0/8\n185.220.101.0/24\n", &bogons, &error));
  bogons.Finish();
  store.Update("firehol_level1", "https://x/1", std::move(bogons));
  const auto lists = store.snapshot();
  EXPECT_TRUE(ThreatListStore::Match(*lists, Ip("10.1.2.3")).empty());
  EXPECT_EQ(ThreatListStore::Match(*lists, Ip("::ffff:185.220.101.7")),
            std::vector<std::string>{"firehol_level1"});
}

TEST(ThreatListsTest, CatalogAndSources) {
  const ThreatList* tor = FindThreatList("tor");
  ASSERT_NE(tor, nullptr);
  EXPECT_EQ(tor->signal, "tor_exit");
  EXPECT_EQ(FindThreatList("nope"), nullptr);
  ThreatListStore store;
  // Spamhaus has an IPv4 and an IPv6 list.
  const auto sources = ThreatListSources({"tor", "spamhaus_drop"}, &store,
                                         "/data", std::chrono::hours(1));
  ASSERT_EQ(sources.size(), 3U);
  EXPECT_EQ(sources[0].cache_file, "/data/threat-tor-0.txt");
  EXPECT_EQ(sources[2].cache_file, "/data/threat-spamhaus_drop-1.txt");
  // Both URLs of a list feed one set.
  std::string error;
  ASSERT_TRUE(sources[1].apply("1.10.16.0/20\n", &error)) << error;
  ASSERT_TRUE(sources[2].apply("{\"cidr\":\"2001:678:254::/48\"}\n", &error))
      << error;
  const auto lists = store.snapshot();
  EXPECT_FALSE(ThreatListStore::Match(*lists, Ip("1.10.20.1")).empty());
  EXPECT_FALSE(ThreatListStore::Match(*lists, Ip("2001:678:254::9")).empty());
}

TEST(ThreatListsTest, ConfigNamesKnownLists) {
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(
      "threat_lists: {enabled: [tor, firehol_level1], refresh: 30m}\n", &config,
      &error))
      << error;
  EXPECT_EQ(config.threat_lists,
            (std::vector<std::string>{"tor", "firehol_level1"}));
  EXPECT_EQ(config.threat_lists_refresh, std::chrono::minutes(30));
  EXPECT_FALSE(
      ParseConfig("threat_lists: {enabled: [badlist]}\n", &config, &error));
  EXPECT_NE(error.find("tor, firehol_level1, spamhaus_drop"),
            std::string::npos);
}

}  // namespace
}  // namespace bot_shield
