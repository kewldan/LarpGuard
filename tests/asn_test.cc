#include "net/asn.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include "common/refresher.h"

namespace bot_shield {
namespace {

constexpr std::string_view kTsv =
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"
    "1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd\n"
    "5.0.0.0\t5.0.0.255\t64500\tDE\tEXAMPLE-HOSTING GmbH\n"
    "2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:"
    "ffff\t64501\tNL\tRESIDENTIAL\r\n"
    "\n";

asio::ip::address Ip(std::string_view text) {
  return asio::ip::make_address(text);
}

TEST(AsnTest, ParsesAndLooksUp) {
  AsnDatabase db;
  std::string error;
  ASSERT_TRUE(AsnDatabase::Parse(kTsv, &db, &error)) << error;
  EXPECT_EQ(db.size(), 4U);

  std::optional<AsnInfo> info = db.Lookup(Ip("1.0.0.1"));
  ASSERT_TRUE(info);
  EXPECT_EQ(info->asn, 13335U);
  EXPECT_EQ(info->country, "US");
  EXPECT_EQ(info->org, "CLOUDFLARENET");
  EXPECT_TRUE(info->hosting);  // Curated.

  info = db.Lookup(Ip("1.0.7.255"));
  ASSERT_TRUE(info);
  EXPECT_EQ(info->asn, 38803U);
  EXPECT_FALSE(info->hosting);

  EXPECT_FALSE(db.Lookup(Ip("1.0.2.1")));  // Not routed.
  EXPECT_FALSE(db.Lookup(Ip("0.255.255.255")));
  EXPECT_FALSE(db.Lookup(Ip("9.9.9.9")));

  info = db.Lookup(Ip("5.0.0.7"));
  ASSERT_TRUE(info);
  EXPECT_TRUE(info->hosting);  // By name.

  info = db.Lookup(Ip("::ffff:1.0.4.9"));  // Mapped IPv4.
  ASSERT_TRUE(info);
  EXPECT_EQ(info->asn, 38803U);

  info = db.Lookup(Ip("2001:db8::1"));
  ASSERT_TRUE(info);
  EXPECT_EQ(info->asn, 64501U);
  EXPECT_EQ(info->country, "NL");
  EXPECT_FALSE(db.Lookup(Ip("2001:db9::1")));
}

TEST(AsnTest, RejectsGarbage) {
  AsnDatabase db;
  std::string error;
  EXPECT_FALSE(AsnDatabase::Parse("", &db, &error));
  EXPECT_FALSE(AsnDatabase::Parse("<html>not a tsv</html>\n", &db, &error));
  EXPECT_FALSE(AsnDatabase::Parse(
      "1.0.0.0\t1.0.0.255\t1\tUS\tA\nx\ty\tz\nq\tw\te\n", &db, &error));
  EXPECT_FALSE(AsnDatabase::Parse("1.0.0.9\t1.0.0.1\t1\tUS\tA\n", &db, &error));
}

TEST(AsnTest, HostingHints) {
  EXPECT_TRUE(IsHostingAs(16509, "AMAZON-02"));
  EXPECT_TRUE(IsHostingAs(1, "Some Cloud Services"));
  EXPECT_TRUE(IsHostingAs(1, "acme vps"));
  EXPECT_FALSE(IsHostingAs(3320, "DTAG Internet service provider"));
}

TEST(RefresherTest, CachesAndRetries) {
  const std::filesystem::path cache =
      std::filesystem::temp_directory_path() /
      std::format("bs-refresher-{}.tsv",
                  ::testing::UnitTest::GetInstance()->random_seed());
  std::filesystem::remove(cache);
  std::atomic<int> fetches{0};
  std::atomic<int> applied{0};
  std::atomic<bool> fail{false};
  std::string last;
  RefreshSource source;
  source.name = "test";
  source.url = "https://example.invalid/data";
  source.cache_file = cache.string();
  source.retry = std::chrono::seconds(3600);
  source.fetch = [&](const std::string&, std::size_t, std::string* data,
                     std::string* error) {
    ++fetches;
    if (fail) {
      *error = "offline";
      return false;
    }
    *data = std::format("v{}", fetches.load());
    return true;
  };
  source.apply = [&](std::string_view data, std::string* error) {
    if (data == "bad") {
      *error = "bad data";
      return false;
    }
    last = std::string(data);
    ++applied;
    return true;
  };
  {
    DataRefresher refresher({source});
    refresher.Start();
    refresher.WaitForPass(1);
    EXPECT_EQ(fetches, 1);
    EXPECT_EQ(last, "v1");
  }
  std::string cached;
  {
    std::ifstream file(cache);
    cached.assign(std::istreambuf_iterator<char>(file), {});
  }
  EXPECT_EQ(cached, "v1");

  // Restart offline: the cache is fresh, so no download is due.
  fail = true;
  last.clear();
  {
    DataRefresher refresher({source});
    refresher.Start();
    refresher.WaitForPass(1);
    EXPECT_EQ(last, "v1");
    EXPECT_EQ(fetches, 1);
    // A forced refresh fails and keeps the data.
    refresher.RefreshNow();
    refresher.WaitForPass(2);
    EXPECT_EQ(fetches, 2);
    EXPECT_EQ(last, "v1");
  }
  std::filesystem::remove(cache);
}

}  // namespace
}  // namespace bot_shield
