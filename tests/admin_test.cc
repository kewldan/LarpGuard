#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/modes.h"
#include "admin/server.h"
#include "common/network.h"
#include "config/config.h"
#include "events/events.h"
#include "net/asn.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "server/verdicts.h"
#include "tls/cert_store.h"

namespace bot_shield {
namespace {

using asio::ip::make_address;
constexpr int64_t kNow = 1'800'000'000;

TEST(NetworkTest, ParseContainsAndFormat) {
  Network network;
  ASSERT_TRUE(Network::Parse("203.0.113.77/24", &network));
  EXPECT_EQ(network.ToString(), "203.0.113.0/24");
  EXPECT_TRUE(network.Contains(make_address("203.0.113.1")));
  EXPECT_TRUE(network.Contains(make_address("::ffff:203.0.113.200")));
  EXPECT_FALSE(network.Contains(make_address("203.0.114.1")));
  EXPECT_FALSE(network.Contains(make_address("2001:db8::1")));

  ASSERT_TRUE(Network::Parse("2001:db8::1", &network));
  EXPECT_EQ(network.ToString(), "2001:db8::1/128");
  ASSERT_TRUE(Network::Parse("::/0", &network));
  EXPECT_TRUE(network.Contains(make_address("2001:db8::1")));
  EXPECT_FALSE(Network::Parse("1.2.3.4/33", &network));
  EXPECT_FALSE(Network::Parse("1.2.3/8", &network));
  EXPECT_FALSE(Network::Parse("1.2.3.4/-1", &network));
}

nlohmann::json Entry(const char* kind, const char* value, const char* action) {
  return {{"kind", kind}, {"value", value}, {"action", action}};
}

TEST(ListStoreTest, ValidationAndTtl) {
  ListEntry entry;
  std::string error;
  EXPECT_FALSE(
      ListStore::FromJson(Entry("mac", "x", "block"), kNow, &entry, &error));
  EXPECT_FALSE(
      ListStore::FromJson(Entry("ip", "nope", "block"), kNow, &entry, &error));
  EXPECT_FALSE(
      ListStore::FromJson(Entry("ip", "1.2.3.4", "tag"), kNow, &entry, &error));
  EXPECT_FALSE(ListStore::FromJson("[]"_json, kNow, &entry, &error));
  auto json = Entry("ip", "10.1.2.3/8", "block");
  json["ttl"] = "1h";
  json["host"] = "Shop.Test";
  ASSERT_TRUE(ListStore::FromJson(json, kNow, &entry, &error)) << error;
  EXPECT_EQ(entry.value, "10.0.0.0/8");
  EXPECT_EQ(entry.expires_at, kNow + 3600);
  EXPECT_EQ(entry.host, "shop.test");
  json["ttl"] = 0;
  EXPECT_FALSE(ListStore::FromJson(json, kNow, &entry, &error));
}

TEST(ListStoreTest, MatchingPrecedenceScopeAndExpiry) {
  ListStore lists("");
  ListEntry entry;
  ListEntry stored;
  std::string error;
  auto block_ip = Entry("ip", "203.0.113.0/24", "block");
  block_ip["host"] = "shop.test";
  ASSERT_TRUE(ListStore::FromJson(block_ip, kNow, &entry, &error));
  ASSERT_TRUE(lists.Add(entry, kNow, &stored, &error)) << error;
  const uint64_t block_id = stored.id;

  ListMatchInput input;
  input.ip = make_address("203.0.113.9");
  input.ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
  input.header_fp = "2:5:abc";
  input.host = "shop.test";
  input.now = kNow;
  auto match = lists.Match(input);
  ASSERT_TRUE(match);
  EXPECT_EQ(match->id, block_id);
  EXPECT_EQ(match->action, Action::kBlock);
  input.host = "blog.test";  // Scoped to shop.test.
  EXPECT_FALSE(lists.Match(input));
  input.host = "shop.test";

  // An allow entry wins over a block entry.
  auto allow_ja4 = Entry("ja4", "t13d1516h2_8daaf6152771_*", "allow");
  allow_ja4["ttl"] = 60;
  ASSERT_TRUE(ListStore::FromJson(allow_ja4, kNow, &entry, &error));
  ASSERT_TRUE(lists.Add(entry, kNow, &stored, &error));
  match = lists.Match(input);
  ASSERT_TRUE(match);
  EXPECT_EQ(match->action, Action::kAllow);
  // ...until it expires.
  input.now = kNow + 61;
  match = lists.Match(input);
  ASSERT_TRUE(match);
  EXPECT_EQ(match->action, Action::kBlock);
  EXPECT_EQ(lists.Entries(kNow + 61).size(), 1u);

  ASSERT_TRUE(lists.Remove(block_id, &error));
  EXPECT_FALSE(lists.Match(input));
  EXPECT_FALSE(lists.Remove(block_id, &error));
}

TEST(ListStoreTest, PersistsToStateFile) {
  const std::string path =
      (std::filesystem::temp_directory_path() / "bs-lists-test.json").string();
  std::remove(path.c_str());
  ListEntry entry;
  ListEntry stored;
  std::string error;
  {
    ListStore lists(path);
    ASSERT_TRUE(lists.Load(kNow, &error)) << error;  // No file yet.
    ASSERT_TRUE(ListStore::FromJson(Entry("header_fp", "1.1:*", "block"), kNow,
                                    &entry, &error));
    ASSERT_TRUE(lists.Add(entry, kNow, &stored, &error)) << error;
    auto expiring = Entry("ip", "1.2.3.4", "allow");
    expiring["ttl"] = 10;
    ASSERT_TRUE(ListStore::FromJson(expiring, kNow, &entry, &error));
    ASSERT_TRUE(lists.Add(entry, kNow, &stored, &error));
  }
  ListStore reloaded(path);
  ASSERT_TRUE(reloaded.Load(kNow + 20, &error)) << error;
  const std::vector<ListEntry> entries = reloaded.Entries(kNow + 20);
  ASSERT_EQ(entries.size(), 1u);  // The expired one is dropped.
  EXPECT_EQ(entries[0].value, "1.1:*");
  // New ids continue after the stored ones.
  ASSERT_TRUE(reloaded.Add(entry, kNow + 20, &stored, &error));
  EXPECT_EQ(stored.id, 3u);
  std::remove(path.c_str());

  std::ofstream(path) << "{not json";
  ListStore broken(path);
  EXPECT_FALSE(broken.Load(kNow, &error));
  std::remove(path.c_str());
}

TEST(AttackModeTest, HostsWildcardsAndExpiry) {
  AttackMode attack(0, 600);
  EXPECT_FALSE(attack.Active("shop.test", kNow));
  std::string error;
  ASSERT_TRUE(
      attack.Enable({"Shop.Test", "admin", kNow, kNow + 60}, kNow, &error))
      << error;
  ASSERT_TRUE(attack.Enable({"*.api.test", "admin", kNow, 0}, kNow, &error));
  EXPECT_TRUE(attack.Active("shop.test", kNow));
  EXPECT_TRUE(attack.Active("v1.api.test", kNow));
  EXPECT_FALSE(attack.Active("other.test", kNow));
  // Expired entries stop matching and disappear.
  EXPECT_FALSE(attack.Active("shop.test", kNow + 60));
  EXPECT_EQ(attack.Entries(kNow + 60).size(), 1u);
  EXPECT_FALSE(attack.Enable({"bad host", "admin", kNow, 0}, kNow, &error));

  ASSERT_TRUE(attack.Enable({"*", "admin", kNow, 0}, kNow, &error));
  EXPECT_TRUE(attack.Active("other.test", kNow));
  EXPECT_TRUE(attack.Disable("*"));
  EXPECT_FALSE(attack.Disable("*"));
  EXPECT_FALSE(attack.Active("other.test", kNow));
}

TEST(AttackModeTest, SwitchesOnAboveAutoRps) {
  RateLimitStore store;
  AttackMode off(0, 600);
  AttackMode attack(10, 600);
  constexpr int64_t kSecond = 1'000'000'000;
  int64_t now_ns = kSecond;
  // At the threshold the host never trips.
  for (int i = 0; i < 300; ++i) {
    EXPECT_FALSE(attack.CountRequest("shop.test", kNow, now_ns, &store));
    EXPECT_FALSE(off.CountRequest("shop.test", kNow, now_ns, &store));
    now_ns += kSecond / 10;
  }
  EXPECT_FALSE(attack.Active("shop.test", kNow));
  // Twice the threshold: about ten seconds of excess switch it on.
  bool switched = false;
  int requests = 0;
  while (!switched && requests < 1000) {
    switched = attack.CountRequest("shop.test", kNow, now_ns, &store);
    now_ns += kSecond / 20;
    ++requests;
  }
  EXPECT_TRUE(switched);
  EXPECT_GT(requests, 150);
  EXPECT_TRUE(attack.Active("shop.test", kNow));
  EXPECT_FALSE(attack.Active("other.test", kNow));
  const std::vector<AttackEntry> entries = attack.Entries(kNow);
  ASSERT_EQ(entries.size(), 1u);
  EXPECT_EQ(entries[0].source, "auto");
  EXPECT_EQ(entries[0].until, kNow + 600);
  EXPECT_FALSE(attack.Active("shop.test", kNow + 600));
}

TEST(DecisionLogTest, BoundedNewestFirstWithFilters) {
  DecisionLog log(3);
  for (int i = 0; i < 5; ++i) {
    DecisionRecord record;
    record.request_id = "r" + std::to_string(i);
    record.host = i % 2 == 0 ? "a.test" : "b.test";
    record.bot_class = i == 4 ? "bot" : "human";
    log.Add(record);
  }
  EXPECT_FALSE(log.Find("r0"));  // Evicted.
  ASSERT_TRUE(log.Find("r3"));
  const auto recent = log.Recent(10, "", "");
  ASSERT_EQ(recent.size(), 3u);
  EXPECT_EQ(recent[0].request_id, "r4");
  EXPECT_EQ(log.Recent(10, "a.test", "").size(), 2u);
  EXPECT_EQ(log.Recent(10, "", "bot").size(), 1u);
  EXPECT_EQ(log.Recent(1, "", "").size(), 1u);
}

class AdminServerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    config_.passthrough_hosts = {"grpc.test"};
    config_.policy.host_modes = {{"shop.test", HostMode::kEnforce}};
    RateLimitSpec spec;
    spec.name = "login";
    spec.key = {"ip"};
    spec.count = 5;
    spec.period = std::chrono::minutes(1);
    spec.hosts = {"shop.test"};
    config_.rate_limits = {spec};
    std::string error;
    std::shared_ptr<const VerdictSet> verdicts;
    ASSERT_TRUE(VerdictSet::Build(config_, &verdicts, &error)) << error;
    verdicts_.set(verdicts);
    context_.config = &config_;
    context_.certificates = &certificates_;
    context_.lists = &lists_;
    context_.decisions = &decisions_;
    context_.rate_limit_store = &store_;
    context_.verdicts = &verdicts_;
    context_.attack = &attack_;
    context_.started_ms = (kNow - 100) * 1000;
    context_.workers = 2;
  }

  AdminResponse Call(std::string_view method, std::string_view target,
                     std::string_view body = "") {
    return HandleAdminRequest(method, target, body, context_, kNow);
  }

  Config config_;
  CertStore certificates_;
  ListStore lists_{""};
  DecisionLog decisions_{100};
  RateLimitStore store_;
  VerdictStore verdicts_;
  AttackMode attack_{0, 600};
  ModeOverrides modes_{""};
  AsnStore asn_;
  AdminContext context_;
};

TEST_F(AdminServerTest, Reload) {
  EXPECT_EQ(Call("POST", "/reload").status, 501);
  EXPECT_EQ(Call("GET", "/reload").status, 405);
  bool succeed = true;
  context_.reload = [&](std::string* summary) {
    *summary = succeed ? "generation 2" : "rules: bad rule";
    return succeed;
  };
  AdminResponse response = Call("POST", "/reload");
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.body["summary"], "generation 2");
  succeed = false;
  response = Call("POST", "/reload");
  EXPECT_EQ(response.status, 422);
  EXPECT_EQ(response.body["error"], "rules: bad rule");
  EXPECT_EQ(Call("GET", "/status").body["verdicts_generation"], 1);
}

TEST_F(AdminServerTest, Status) {
  const AdminResponse response = Call("GET", "/status");
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.body["uptime_s"], 100);
  EXPECT_EQ(response.body["mode"], "shadow");
  EXPECT_EQ(response.body["workers"], 2);
  EXPECT_EQ(Call("POST", "/status").status, 405);
  EXPECT_EQ(Call("GET", "/nope").status, 404);
}

TEST_F(AdminServerTest, Policy) {
  AdminResponse response = Call("GET", "/policy?host=Shop.Test");
  ASSERT_EQ(response.status, 200);
  EXPECT_EQ(response.body["mode"], "enforce");
  EXPECT_EQ(response.body["mode_source"], "policy.hosts");
  EXPECT_EQ(response.body["route"], "passthrough (no certificate)");
  EXPECT_EQ(response.body["rate_limits"], nlohmann::json::array({"login"}));
  response = Call("GET", "/policy?host=grpc.test");
  EXPECT_EQ(response.body["route"], "passthrough (policy)");
  EXPECT_EQ(response.body["mode_source"], "mode");
}

TEST_F(AdminServerTest, PolicyOverview) {
  const AdminResponse response = Call("GET", "/policy");
  ASSERT_EQ(response.status, 200);
  EXPECT_EQ(response.body["default"], "shadow");
  ASSERT_EQ(response.body["policy_hosts"].size(), 1u);
  EXPECT_EQ(response.body["policy_hosts"][0]["host"], "shop.test");
  EXPECT_EQ(response.body["policy_hosts"][0]["mode"], "enforce");
  EXPECT_TRUE(response.body["console"].empty());
  EXPECT_TRUE(response.body["labels"].empty());
  EXPECT_EQ(response.body["passthrough_hosts"][0], "grpc.test");
}

TEST_F(AdminServerTest, ConsoleModes) {
  EXPECT_EQ(
      Call("POST", "/policy", R"({"host":"shop.test","mode":"off"})").status,
      404);  // No store yet.
  context_.modes = &modes_;
  context_.publish_modes = [this] {
    verdicts_.set(WithConsoleModes(*verdicts_.snapshot(), modes_.Entries()));
  };
  AdminResponse response =
      Call("POST", "/policy", R"({"host":"Shop.Test","mode":"shadow"})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(response.body["host"], "shop.test");
  // The console beats policy.hosts (enforce) and applies at once.
  response = Call("GET", "/policy?host=shop.test");
  EXPECT_EQ(response.body["mode"], "shadow");
  EXPECT_EQ(response.body["mode_source"], "console");
  EXPECT_EQ(Call("GET", "/policy").body["console"][0]["mode"], "shadow");
  EXPECT_EQ(Call("GET", "/status").body["verdicts_generation"], 2);

  ASSERT_EQ(Call("POST", "/policy", R"({"host":"*.api.test","mode":"enforce"})")
                .status,
            200);
  EXPECT_EQ(Call("GET", "/policy?host=v1.api.test").body["mode_source"],
            "console");
  EXPECT_EQ(Call("POST", "/policy", R"({"host":"a b","mode":"off"})").status,
            400);
  EXPECT_EQ(
      Call("POST", "/policy", R"({"host":"a.test","mode":"loud"})").status,
      400);
  EXPECT_EQ(Call("POST", "/policy", "[]").status, 400);
  EXPECT_EQ(Call("PUT", "/policy").status, 405);

  EXPECT_EQ(Call("DELETE", "/policy/shop.test").status, 200);
  response = Call("GET", "/policy?host=shop.test");
  EXPECT_EQ(response.body["mode"], "enforce");
  EXPECT_EQ(response.body["mode_source"], "policy.hosts");
  EXPECT_EQ(Call("DELETE", "/policy/shop.test").status, 404);
}

TEST_F(AdminServerTest, ConfigView) {
  const AdminResponse response = Call("GET", "/config");
  ASSERT_EQ(response.status, 200);
  const nlohmann::json& body = response.body;
  EXPECT_EQ(body["generation"], 1);
  EXPECT_GT(body["built_at_ms"].get<int64_t>(), 0);
  EXPECT_EQ(body["policy"]["suspicious_threshold"], 30);
  EXPECT_EQ(body["policy"]["bot_threshold"], 70);
  EXPECT_EQ(body["policy"]["bot_action"], "block");
  EXPECT_EQ(body["rate_limits"][0]["name"], "login");
  EXPECT_EQ(body["rate_limits"][0]["period_ms"], 60000);
  EXPECT_EQ(body["rate_limits"][0]["key"][0], "ip");
  EXPECT_TRUE(body["throttle"].is_null());
  EXPECT_FALSE(body["library"]["weights"].empty());
  EXPECT_TRUE(body["library"]["automation"].is_array());
  EXPECT_FALSE(body["crawlers"]["catalog"].empty());
  EXPECT_FALSE(body["model"]["loaded"]);
  // No secrets or paths.
  EXPECT_FALSE(body.contains("captcha_secret_file"));
  EXPECT_FALSE(body["captcha"].contains("site_key"));
  EXPECT_EQ(Call("POST", "/config").status, 405);
}

TEST_F(AdminServerTest, RulesTest) {
  AdminResponse response = Call(
      "POST", "/rules/test", R"({"when":"score > 40 and\n  hosst == \"a\""})");
  ASSERT_EQ(response.status, 422);
  EXPECT_NE(response.body["error"].get<std::string>().find("unknown name"),
            std::string::npos);
  EXPECT_EQ(response.body["column"], 18);

  response = Call("POST", "/rules/test", R"({"when":"score > 40"})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(response.body["evaluated"], 0);
  EXPECT_EQ(response.body["references"], nlohmann::json::array({"score"}));

  response = Call(
      "POST", "/rules/test",
      R"({"when":"score > 40 and ua_tool == \"curl\" and )"
      R"(cidr(\"203.0.113.0/24\") and \"ua_tls_mismatch\" in reasons",)"
      R"("samples":[)"
      R"({"score":80,"user_agent":"curl/8.7.1","ip_prefix":"203.0.113.0/24",)"
      R"("reasons":["ua_tls_mismatch"]},)"
      R"({"score":80,"user_agent":"curl/8.7.1","ip_prefix":"198.51.100.0/24",)"
      R"("reasons":["ua_tls_mismatch"]},)"
      R"({"score":10,"user_agent":"curl/8.7.1","ip_prefix":"203.0.113.0/24"},)"
      R"({"score":90,"user_agent":"Mozilla/5.0","ip_prefix":"203.0.113.0/24",)"
      R"("reasons":["ua_tls_mismatch"]}]})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(response.body["evaluated"], 4);
  EXPECT_EQ(response.body["matched"], nlohmann::json::array({0}));

  // Round trips arrive in microseconds as in events; null is unknown (-1,
  // which "< 10" alone would match).
  response = Call("POST", "/rules/test",
                  R"({"when":"handshake_ms > 100 and tcp_rtt_ms >= 0 and )"
                  R"(tcp_rtt_ms < 10",)"
                  R"("samples":[{"tcp_rtt_us":4000,"handshake_us":180000},)"
                  R"({"tcp_rtt_us":null,"handshake_us":180000},)"
                  R"({"tcp_rtt_us":90000,"handshake_us":95000}]})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(response.body["matched"], nlohmann::json::array({0}));

  EXPECT_EQ(Call("POST", "/rules/test",
                 R"({"when":"true","samples":[{"score":"x"}]})")
                .status,
            400);
  EXPECT_EQ(Call("POST", "/rules/test", R"({"samples":[]})").status, 400);
  EXPECT_EQ(Call("POST", "/rules/test", "nope").status, 400);
  EXPECT_EQ(Call("GET", "/rules/test").status, 405);
}

TEST_F(AdminServerTest, AsnNames) {
  AdminResponse response = Call("GET", "/asn?numbers=64500");
  ASSERT_EQ(response.status, 200);
  EXPECT_FALSE(response.body["loaded"]);
  auto database = std::make_shared<AsnDatabase>();
  std::string error;
  ASSERT_TRUE(AsnDatabase::Parse(
      "5.0.0.0\t5.0.0.255\t64500\tDE\tEXAMPLE-HOSTING GmbH\n", database.get(),
      &error))
      << error;
  asn_.set(database);
  context_.asn = &asn_;
  response = Call("GET", "/asn?numbers=64500,64511");
  ASSERT_EQ(response.status, 200);
  EXPECT_TRUE(response.body["loaded"]);
  ASSERT_EQ(response.body["asns"].size(), 1u);
  EXPECT_EQ(response.body["asns"][0]["org"], "EXAMPLE-HOSTING GmbH");
  EXPECT_EQ(response.body["asns"][0]["hosting"], true);
  EXPECT_EQ(Call("GET", "/asn?numbers=AS1").status, 400);
}

TEST_F(AdminServerTest, ListsCrud) {
  AdminResponse response =
      Call("POST", "/lists",
           R"({"kind":"ip","value":"198.51.100.7","action":"block",)"
           R"("ttl":"10m","comment":"scraper"})");
  ASSERT_EQ(response.status, 201) << response.body.dump();
  const uint64_t id = response.body["id"];
  EXPECT_EQ(response.body["value"], "198.51.100.7/32");
  EXPECT_EQ(response.body["expires_at"], kNow + 600);

  response = Call("GET", "/lists");
  ASSERT_EQ(response.body["entries"].size(), 1u);
  EXPECT_EQ(response.body["entries"][0]["comment"], "scraper");

  EXPECT_EQ(Call("POST", "/lists", "{bad").status, 400);
  EXPECT_EQ(Call("POST", "/lists", R"({"kind":"ip"})").status, 400);
  EXPECT_EQ(Call("DELETE", "/lists/abc").status, 400);
  EXPECT_EQ(Call("DELETE", "/lists/999").status, 404);
  EXPECT_EQ(Call("DELETE", "/lists/" + std::to_string(id)).status, 200);
  EXPECT_TRUE(Call("GET", "/lists").body["entries"].empty());
  EXPECT_EQ(Call("PUT", "/lists").status, 405);
}

TEST_F(AdminServerTest, Decisions) {
  DecisionRecord record;
  record.request_id = "inst-1-1";
  record.host = "shop.test";
  record.bot_class = "bot";
  record.reasons = {"ua_tls_mismatch"};
  decisions_.Add(record);
  AdminResponse response = Call("GET", "/decisions/inst-1-1");
  ASSERT_EQ(response.status, 200);
  EXPECT_EQ(response.body["reasons"][0], "ua_tls_mismatch");
  EXPECT_EQ(Call("GET", "/decisions/unknown").status, 404);
  response = Call("GET", "/decisions?host=shop.test&class=bot&limit=5");
  EXPECT_EQ(response.body["decisions"].size(), 1u);
  EXPECT_TRUE(Call("GET", "/decisions?class=human").body["decisions"].empty());
  EXPECT_EQ(Call("GET", "/decisions?limit=0").status, 400);
  EXPECT_EQ(Call("GET", "/decisions?limit=x").status, 400);
}

TEST_F(AdminServerTest, DecisionsCarryPrefixAndEventHash) {
  EventSettings events;
  events.ip_salt = "salt";
  context_.event_settings = &events;
  DecisionRecord record;
  record.request_id = "inst-1-2";
  record.ip = "203.0.113.77";
  decisions_.Add(record);
  const AdminResponse response = Call("GET", "/decisions/inst-1-2");
  ASSERT_EQ(response.status, 200);
  EXPECT_EQ(response.body["ip_prefix"], "203.0.113.0/24");
  EXPECT_EQ(response.body["ip_hash"],
            IpHash(asio::ip::make_address("203.0.113.77"), "salt"));
  record.request_id = "inst-1-3";
  record.ip = "2001:db8:4f:1::9";
  decisions_.Add(record);
  EXPECT_EQ(Call("GET", "/decisions?limit=1").body["decisions"][0]["ip_prefix"],
            "2001:db8:4f::/48");
}

TEST_F(AdminServerTest, AttackMode) {
  AdminResponse response =
      Call("POST", "/attack", R"({"host":"Shop.Test","ttl":"1h"})");
  ASSERT_EQ(response.status, 201) << response.body.dump();
  EXPECT_EQ(response.body["host"], "shop.test");
  EXPECT_EQ(response.body["until"], kNow + 3600);
  EXPECT_TRUE(attack_.Active("shop.test", kNow));
  ASSERT_EQ(Call("POST", "/attack", R"({"host":"*"})").status, 201);

  response = Call("GET", "/attack");
  ASSERT_EQ(response.status, 200);
  ASSERT_EQ(response.body["entries"].size(), 2u);
  EXPECT_EQ(response.body["entries"][0]["source"], "admin");
  EXPECT_FALSE(response.body["entries"][1].contains("until"));
  EXPECT_EQ(Call("GET", "/status").body["attack_entries"], 2);

  EXPECT_EQ(Call("POST", "/attack", "{bad").status, 400);
  EXPECT_EQ(Call("POST", "/attack", R"({"host":"a b"})").status, 400);
  EXPECT_EQ(Call("POST", "/attack", R"({"host":"x.test","ttl":"-1s"})").status,
            400);
  EXPECT_EQ(Call("DELETE", "/attack/*").status, 200);
  EXPECT_EQ(Call("DELETE", "/attack/shop.test").status, 200);
  EXPECT_EQ(Call("DELETE", "/attack/shop.test").status, 404);
  EXPECT_FALSE(attack_.Active("shop.test", kNow));
  EXPECT_EQ(Call("PUT", "/attack").status, 405);
}

TEST(ModeOverridesTest, PersistsAndValidates) {
  const std::string path =
      (std::filesystem::temp_directory_path() / "bs_modes_test.json").string();
  std::filesystem::remove(path);
  std::string error;
  {
    ModeOverrides modes(path);
    ASSERT_TRUE(modes.Load(&error)) << error;  // Missing file: empty.
    EXPECT_TRUE(modes.Entries().empty());
    ASSERT_TRUE(modes.Set("Shop.Test", HostMode::kEnforce, &error)) << error;
    ASSERT_TRUE(modes.Set("*.api.test", HostMode::kOff, &error)) << error;
    ASSERT_TRUE(modes.Set("shop.test", HostMode::kShadow, &error)) << error;
    EXPECT_FALSE(modes.Set("bad host", HostMode::kOff, &error));
    EXPECT_FALSE(modes.Remove("none.test", &error));
  }
  {
    ModeOverrides modes(path);
    ASSERT_TRUE(modes.Load(&error)) << error;
    const auto entries = modes.Entries();
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].first, "*.api.test");  // JSON object order.
    EXPECT_EQ(entries[0].second, HostMode::kOff);
    EXPECT_EQ(entries[1].first, "shop.test");
    EXPECT_EQ(entries[1].second, HostMode::kShadow);
    ASSERT_TRUE(modes.Remove("shop.test", &error)) << error;
  }
  {
    std::ofstream(path) << R"({"shop.test": "loud"})";
    ModeOverrides modes(path);
    EXPECT_FALSE(modes.Load(&error));
  }
  std::filesystem::remove(path);
}

TEST(AdminConfigTest, Parses) {
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(
      "admin: {socket: /run/bs.sock, state_file: /var/lib/bs/lists.json, "
      "decisions: 500}\n",
      &config, &error))
      << error;
  EXPECT_EQ(config.admin_socket, "/run/bs.sock");
  EXPECT_EQ(config.admin_state_file, "/var/lib/bs/lists.json");
  EXPECT_TRUE(config.admin_modes_file.empty());
  ASSERT_TRUE(ParseConfig("admin: {modes_file: /var/lib/bs/modes.json}\n",
                          &config, &error))
      << error;
  EXPECT_EQ(config.admin_modes_file, "/var/lib/bs/modes.json");
  EXPECT_EQ(config.admin_decisions, 500u);
  EXPECT_FALSE(ParseConfig("admin: {port: 1}\n", &config, &error));
  EXPECT_FALSE(ParseConfig("admin: {decisions: -1}\n", &config, &error));
}

}  // namespace
}  // namespace bot_shield
