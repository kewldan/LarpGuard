#include "net/geoip.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <iterator>
#include <string>
#include <vector>

#include "common/compress.h"
#include "config/config.h"

namespace bot_shield {
namespace {

asio::ip::address Ip(const char* text) { return asio::ip::make_address(text); }

TEST(GeoipTest, ParsesAndLooksUp) {
  GeoDatabase db;
  std::string error;
  ASSERT_TRUE(
      GeoDatabase::Parse("0.0.0.0,0.255.255.255,ZZ\n"
                         "1.0.0.0,1.0.0.255,AU\r\n"
                         "8.8.8.0,8.8.8.255,US\n"
                         "2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:"
                         "ffff:ffff,IE\n",
                         &db, &error))
      << error;
  EXPECT_EQ(db.size(), 4U);
  EXPECT_EQ(db.Lookup(Ip("1.0.0.7")), "AU");
  EXPECT_EQ(db.Lookup(Ip("::ffff:8.8.8.8")), "US");
  EXPECT_EQ(db.Lookup(Ip("2a00:1450:4001::1")), "IE");
  EXPECT_EQ(db.Lookup(Ip("0.1.2.3")), "");  // ZZ: unassigned.
  EXPECT_EQ(db.Lookup(Ip("9.9.9.9")), "");  // Between ranges.
  EXPECT_EQ(db.Lookup(Ip("2001:db8::1")), "");

  GeoDatabase empty;
  EXPECT_FALSE(GeoDatabase::Parse("<html>not found</html>\n", &empty, &error));
  EXPECT_FALSE(GeoDatabase::Parse("1.0.0.0,1.0.0.255,AU\nbad\nworse\n", &empty,
                                  &error));  // 2 of 3 bad.
}

TEST(GeoipTest, MonthInUrl) {
  EXPECT_EQ(
      GeoUrlForMonth("https://x/dbip-country-lite-{month}.csv.gz", 2026, 3),
      "https://x/dbip-country-lite-2026-03.csv.gz");
  EXPECT_EQ(GeoUrlForMonth("https://x/static.csv", 2026, 3),
            "https://x/static.csv");
}

TEST(GeoipTest, TriesThisMonthThenLast) {
  using std::chrono::January;
  using std::chrono::March;
  const std::string url = "https://x/c-{month}.csv.gz";
  EXPECT_EQ(GeoUrlsToTry(url, std::chrono::sys_days{std::chrono::year{2026} /
                                                    March / 2}),
            (std::vector<std::string>{"https://x/c-2026-03.csv.gz",
                                      "https://x/c-2026-02.csv.gz"}));
  // Across the year.
  EXPECT_EQ(GeoUrlsToTry(url, std::chrono::sys_days{std::chrono::year{2026} /
                                                    January / 3})[1],
            "https://x/c-2025-12.csv.gz");
  EXPECT_EQ(GeoUrlsToTry("https://x/static.csv", std::chrono::sys_days{}),
            std::vector<std::string>{"https://x/static.csv"});
}

TEST(GeoipTest, Config) {
  Config config;
  std::string error;
  ASSERT_TRUE(
      ParseConfig("geoip: {url: \"https://x/{month}.csv.gz\", "
                  "refresh: 12h}\n",
                  &config, &error))
      << error;
  EXPECT_EQ(config.geoip_url, "https://x/{month}.csv.gz");
  EXPECT_EQ(config.geoip_refresh, std::chrono::hours(12));
  EXPECT_FALSE(ParseConfig("geoip: {url: \"ftp://x\"}\n", &config, &error));
}

// The real file, when BOT_SHIELD_GEOIP_CSV points at a download of
// dbip-country-lite-YYYY-MM.csv.gz.
TEST(GeoipTest, RealDatabase) {
  const char* path = std::getenv("BOT_SHIELD_GEOIP_CSV");
  if (path == nullptr) GTEST_SKIP() << "BOT_SHIELD_GEOIP_CSV not set";
  std::ifstream file(path, std::ios::binary);
  const std::string gz((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
  std::string csv;
  std::string error;
  ASSERT_TRUE(Gunzip(gz, std::size_t{512} << 20, &csv, &error)) << error;
  GeoDatabase db;
  ASSERT_TRUE(GeoDatabase::Parse(csv, &db, &error)) << error;
  EXPECT_GT(db.size(), 500000U);
  EXPECT_EQ(db.Lookup(Ip("1.0.0.1")), "AU");
  EXPECT_EQ(db.Lookup(Ip("127.0.0.1")), "");
}

}  // namespace
}  // namespace bot_shield
