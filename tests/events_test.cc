#include "events/events.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <nlohmann/json.hpp>
#include <string>

#include "fp/http_request.h"

namespace bot_shield {
namespace {

using asio::ip::make_address;

TEST(EventsTest, IpPrefix) {
  EXPECT_EQ(IpPrefix(make_address("203.0.113.77")), "203.0.113.0/24");
  EXPECT_EQ(IpPrefix(make_address("::ffff:198.51.100.9")), "198.51.100.0/24");
  EXPECT_EQ(IpPrefix(make_address("2001:db8:1:2:3::4")), "2001:db8:1::/48");
}

TEST(EventsTest, IpHashIsKeyedAndStable) {
  const auto address = make_address("203.0.113.77");
  const std::string hash = IpHash(address, "salt");
  EXPECT_EQ(hash.size(), 16u);
  EXPECT_EQ(IpHash(address, "salt"), hash);
  EXPECT_NE(IpHash(address, "other"), hash);
  EXPECT_NE(IpHash(make_address("203.0.113.78"), "salt"), hash);
}

TEST(EventsTest, PathGroup) {
  EXPECT_EQ(PathGroup("/"), "/");
  EXPECT_EQ(PathGroup(""), "/");
  EXPECT_EQ(PathGroup("/items/123?q=secret#x"), "/items/:n");
  EXPECT_EQ(PathGroup("/u/550e8400-e29b-41d4-a716-446655440000/edit"),
            "/u/:uuid/edit");
  EXPECT_EQ(PathGroup("/blob/0123456789abcdef0123"), "/blob/:hex");
  EXPECT_EQ(PathGroup("/a/" + std::string(80, 'x') + "/b"), "/a/:long/b");
  EXPECT_EQ(PathGroup("http://shop.test/p/7?x=1"), "/p/:n");
  EXPECT_EQ(PathGroup("/dir/"), "/dir/");
  EXPECT_LE(PathGroup("/" + std::string(2000, 'a') + "/b").size(), 256u);
}

ConnectionRecord Record() {
  ConnectionRecord record;
  record.id = 42;
  record.started_ms = 1000;
  record.listener = "https";
  record.peer = make_address("203.0.113.77");
  record.server_name = "shop.test";
  record.route = "terminate";
  record.reason = "certificate";
  record.ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1";
  record.tcp_fingerprint = "4:64:64240:1460:7:MSTNW:df";
  record.bytes_in = 10;
  record.bytes_out = 20;
  record.requests = 1;
  return record;
}

TEST(EventsTest, ConnectionEventHasNoFullAddress) {
  const EventSettings settings{"inst", "salt", true};
  const auto json =
      nlohmann::json::parse(ConnectionEventJson(Record(), settings, 1500));
  EXPECT_EQ(json["conn_id"], 42);
  EXPECT_EQ(json["instance"], "inst");
  EXPECT_EQ(json["duration_ms"], 500);
  EXPECT_EQ(json["ip_prefix"], "203.0.113.0/24");
  EXPECT_EQ(json["sni"], "shop.test");
  EXPECT_EQ(json["ja4"], "t13d1516h2_8daaf6152771_e5627efa2ab1");
  EXPECT_FALSE(json.contains("h2_fp"));  // Empty fields are omitted.
  EXPECT_EQ(json.dump().find("203.0.113.77"), std::string::npos);
}

TEST(EventsTest, RequestEvent) {
  HttpRequest request;
  request.version = "1.1";
  request.method = "GET";
  request.authority = "Shop.Test:443";
  request.target = "/p/12?token=secret";
  request.header_names = {"Host", "User-Agent", "Cookie"};
  request.headers = {{"host", "Shop.Test:443"},
                     {"user-agent", "Mozilla/5.0"},
                     {"cookie", "session=secret"}};
  const EventSettings settings{"inst", "salt", true};
  const std::string text =
      RequestEventJson(Record(), request, 3, settings, 2000);
  const auto json = nlohmann::json::parse(text);
  EXPECT_EQ(json["seq"], 3);
  EXPECT_EQ(json["host"], "shop.test");
  EXPECT_EQ(json["path_group"], "/p/:n");
  EXPECT_EQ(json["user_agent"], "Mozilla/5.0");
  EXPECT_EQ(json["has_cookie"], true);
  EXPECT_EQ(json["header_names"].size(), 3u);
  EXPECT_TRUE(json["header_fp"].get<std::string>().starts_with("1.1:3:"));
  // Query strings and cookie values never leave the gateway.
  EXPECT_EQ(text.find("secret"), std::string::npos);
#if BOT_SHIELD_FOXIO
  EXPECT_TRUE(json.contains("ja4h"));
#endif
}

TEST(EventsTest, InvalidUtf8IsReplaced) {
  HttpRequest request;
  request.version = "1.1";
  request.method = "GET";
  request.headers = {{"user-agent", std::string("bad\xff\xfe", 5)}};
  const EventSettings settings{"inst", "salt", true};
  std::string text;
  ASSERT_NO_THROW(text = RequestEventJson(Record(), request, 1, settings, 0));
  EXPECT_NO_THROW(static_cast<void>(nlohmann::json::parse(text)));
}

}  // namespace
}  // namespace bot_shield
