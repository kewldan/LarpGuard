#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/modes.h"
#include "admin/server.h"
#include "admin/settings.h"
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

  ASSERT_TRUE(ListStore::FromJson(Entry("asn", "AS64500", "block"), kNow,
                                  &entry, &error))
      << error;
  EXPECT_EQ(entry.value, "64500");
  EXPECT_EQ(entry.asn, 64500u);
  EXPECT_FALSE(
      ListStore::FromJson(Entry("asn", "AS0", "block"), kNow, &entry, &error));
  EXPECT_FALSE(
      ListStore::FromJson(Entry("asn", "AS-1", "block"), kNow, &entry, &error));
  EXPECT_FALSE(ListStore::FromJson(Entry("asn", "4294967296", "block"), kNow,
                                   &entry, &error));
}

TEST(ListStoreTest, AsnEntriesAndUpdates) {
  ListStore lists("");
  ListEntry entry;
  ListEntry stored;
  std::string error;
  auto json = Entry("asn", "as14061", "block");
  json["ttl"] = 60;
  ASSERT_TRUE(ListStore::FromJson(json, kNow, &entry, &error));
  ASSERT_TRUE(lists.Add(entry, kNow, &stored, &error)) << error;
  ListMatchInput input;
  input.ip = make_address("198.51.100.7");
  input.host = "shop.test";
  input.now = kNow;
  EXPECT_FALSE(lists.Match(input));  // AS unknown.
  input.asn = 14061;
  auto match = lists.Match(input);
  ASSERT_TRUE(match);
  EXPECT_EQ(match->action, Action::kBlock);
  input.asn = 15169;
  EXPECT_FALSE(lists.Match(input));

  // Extended before it expires, then made permanent; comment replaced.
  bool found = false;
  ASSERT_TRUE(lists.Update(stored.id, {{"ttl", "1h"}, {"comment", "hoster"}},
                           kNow + 30, &stored, &found, &error))
      << error;
  EXPECT_EQ(stored.expires_at, kNow + 30 + 3600);
  EXPECT_EQ(stored.comment, "hoster");
  input.asn = 14061;
  input.now = kNow + 120;
  EXPECT_TRUE(lists.Match(input));
  ASSERT_TRUE(lists.Update(stored.id, {{"ttl", nullptr}}, kNow + 30, &stored,
                           &found, &error));
  EXPECT_EQ(stored.expires_at, 0);
  EXPECT_FALSE(
      lists.Update(stored.id, {{"value", "1"}}, kNow, &stored, &found, &error));
  EXPECT_FALSE(found);
  EXPECT_FALSE(
      lists.Update(stored.id, {{"ttl", 0}}, kNow, &stored, &found, &error));
  EXPECT_FALSE(lists.Update(999, {{"ttl", 60}}, kNow, &stored, &found, &error));
  EXPECT_FALSE(found);
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
  AttackMode attack(0, 0, 600);
  EXPECT_FALSE(attack.Active("shop.test", kNow));
  std::string error;
  ASSERT_TRUE(attack.Enable({.host = "Shop.Test",
                             .source = "admin",
                             .since = kNow,
                             .until = kNow + 60},
                            kNow, &error))
      << error;
  ASSERT_TRUE(attack.Enable(
      {.host = "*.api.test", .source = "admin", .since = kNow, .until = 0},
      kNow, &error));
  EXPECT_TRUE(attack.Active("shop.test", kNow));
  EXPECT_TRUE(attack.Active("v1.api.test", kNow));
  EXPECT_FALSE(attack.Active("other.test", kNow));
  // Expired entries stop matching and disappear.
  EXPECT_FALSE(attack.Active("shop.test", kNow + 60));
  EXPECT_EQ(attack.Entries(kNow + 60).size(), 1u);
  EXPECT_FALSE(attack.Enable(
      {.host = "bad host", .source = "admin", .since = kNow, .until = 0}, kNow,
      &error));

  ASSERT_TRUE(
      attack.Enable({.host = "*", .source = "admin", .since = kNow, .until = 0},
                    kNow, &error));
  EXPECT_TRUE(attack.Active("other.test", kNow));
  EXPECT_TRUE(attack.Disable("*", kNow));
  EXPECT_FALSE(attack.Disable("*", kNow));
  EXPECT_FALSE(attack.Active("other.test", kNow));
}

TEST(AttackModeTest, PicksTheNarrowestDominantSignature) {
  std::vector<AttackSample> samples;
  EXPECT_FALSE(DominantSignature(samples));  // Too few.
  for (int i = 0; i < 40; ++i) {
    samples.push_back({std::format("198.51.{}.0/24", i), "t13d_chrome", 64500});
  }
  // Spread over networks, one AS: the AS.
  auto signature = DominantSignature(samples);
  ASSERT_TRUE(signature);
  EXPECT_EQ(*signature, (std::pair<std::string, std::string>{"asn", "64500"}));
  // One network wins over its AS.
  for (auto& sample : samples) sample.ip_prefix = "203.0.113.0/24";
  signature = DominantSignature(samples);
  ASSERT_TRUE(signature);
  EXPECT_EQ(signature->first, "ip_prefix");
  // Spread over networks and ASes, one TLS stack: the JA4.
  for (int i = 0; i < 40; ++i) {
    samples[i].ip_prefix = std::format("198.51.{}.0/24", i);
    samples[i].asn = 64000 + static_cast<uint32_t>(i);
  }
  signature = DominantSignature(samples);
  ASSERT_TRUE(signature);
  EXPECT_EQ(signature->first, "ja4");
  // Nothing shared: the whole host.
  for (int i = 0; i < 40; ++i) samples[i].ja4 = std::format("t13d_{}", i);
  EXPECT_FALSE(DominantSignature(samples));
}

TEST(AttackModeTest, NarrowsToTheAttackersThenWidens) {
  RateLimitStore store;
  AttackMode attack(10, 0, 600);
  constexpr int64_t kSecond = 1'000'000'000;
  int64_t now_ns = kSecond;
  // A flood from one network (90 %) among ordinary clients.
  const auto subject = [](int i) {
    return i % 10 == 0 ? AttackSubject{.host = "shop.test",
                                       .ip_prefix = "192.0.2.0/24",
                                       .ja4 = "t13d_chrome",
                                       .asn = 64501}
                       : AttackSubject{.host = "shop.test",
                                       .ip_prefix = "203.0.113.0/24",
                                       .ja4 = "t13d_go",
                                       .asn = 64500};
  };
  bool switched = false;
  int i = 0;
  for (; !switched && i < 2000; ++i) {
    const AttackSubject who = subject(i);
    if (attack.Active(who, kNow)) continue;
    switched = attack.CountRequest(who, kNow, now_ns, &store);
    now_ns += kSecond / 40;
  }
  ASSERT_TRUE(switched);
  std::vector<AttackEntry> entries = attack.Entries(kNow);
  ASSERT_EQ(entries.size(), 1u);
  EXPECT_EQ(entries[0].kind, "ip_prefix");
  EXPECT_EQ(entries[0].value, "203.0.113.0/24");
  // Only the attackers are challenged; the host as such is not.
  EXPECT_TRUE(attack.Active(subject(1), kNow));
  EXPECT_FALSE(attack.Active(subject(0), kNow));
  EXPECT_FALSE(attack.Active("shop.test", kNow));

  // The flood goes on from everywhere: the rest trips again, up to the
  // whole host.
  for (int step = 0; step < 4000 && !attack.Active("shop.test", kNow); ++step) {
    const std::string prefix = std::format("10.{}.0.0/24", step);
    const std::string ja4 = std::format("t13d_{}", step);
    const AttackSubject who{
        .host = "shop.test", .ip_prefix = prefix, .ja4 = ja4, .asn = 0};
    if (attack.Active(who, kNow)) continue;
    attack.CountRequest(who, kNow, now_ns, &store);
    now_ns += kSecond / 40;
  }
  EXPECT_TRUE(attack.Active("shop.test", kNow));
  EXPECT_TRUE(attack.Disable("shop.test", kNow));
  EXPECT_TRUE(attack.Entries(kNow).empty());  // Every entry of the host.
}

TEST(AttackModeTest, SwitchesOnAboveAutoRps) {
  RateLimitStore store;
  AttackMode off(0, 0, 600);
  AttackMode attack(10, 0, 600);
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

TEST(AttackModeTest, TotalRateCoversEveryHost) {
  // A flood spread thin over many hosts: no host is above auto_rps, the
  // total is above auto_rps_total.
  RateLimitStore store;
  AttackMode attack(100, 10, 600);
  constexpr int64_t kSecond = 1'000'000'000;
  int64_t now_ns = kSecond;
  bool switched = false;
  for (int i = 0; !switched && i < 2000; ++i) {
    const std::string host = std::format("site{}.test", i % 50);
    const std::string prefix = std::format("10.{}.0.0/24", i);
    const AttackSubject who{.host = host, .ip_prefix = prefix, .asn = 0};
    switched = attack.CountRequest(who, kNow, now_ns, &store);
    now_ns += kSecond / 20;
  }
  ASSERT_TRUE(switched);
  const std::vector<AttackEntry> entries = attack.Entries(kNow);
  ASSERT_EQ(entries.size(), 1u);
  EXPECT_EQ(entries[0].host, "*");
  EXPECT_TRUE(entries[0].kind.empty());
  EXPECT_EQ(entries[0].threshold, 10);
  EXPECT_TRUE(attack.Active("anything.test", kNow));
}

TEST(AttackModeTest, KeepsHistoryAndSurvivesRestarts) {
  const std::string path =
      (std::filesystem::temp_directory_path() / "bs-attack-test.json").string();
  std::remove(path.c_str());
  std::string error;
  {
    AttackMode attack(0, 0, 600, path);
    ASSERT_TRUE(attack.Load(kNow, &error)) << error;  // No file yet.
    ASSERT_TRUE(attack.Enable({.host = "shop.test",
                               .source = "admin",
                               .since = kNow,
                               .until = kNow + 60},
                              kNow, &error));
    // Renewed: the same activation, a later end.
    ASSERT_TRUE(attack.Enable({.host = "shop.test",
                               .source = "admin",
                               .since = kNow,
                               .until = kNow + 3600},
                              kNow + 10, &error));
    ASSERT_TRUE(attack.Enable({.host = "api.test",
                               .source = "auto",
                               .since = kNow,
                               .until = kNow + 600,
                               .kind = "asn",
                               .value = "64500",
                               .threshold = 50},
                              kNow, &error));
    ASSERT_TRUE(attack.Enable(
        {.host = "old.test", .source = "admin", .since = kNow, .until = 0},
        kNow, &error));
    EXPECT_TRUE(attack.Disable("old.test", kNow + 5));
    const std::vector<AttackRecord> history = attack.History(kNow + 20);
    ASSERT_EQ(history.size(), 3u);
    EXPECT_EQ(history[0].entry.host, "old.test");  // Newest first.
    EXPECT_EQ(history[0].ended, kNow + 5);
    EXPECT_EQ(history[2].entry.host, "shop.test");
    EXPECT_EQ(history[2].entry.until, kNow + 3600);
    EXPECT_EQ(history[2].ended, 0);
    ASSERT_TRUE(attack.SaveIfChanged(kNow + 20, &error)) << error;
  }
  // Restarted after api.test expired.
  AttackMode restarted(0, 0, 600, path);
  ASSERT_TRUE(restarted.Load(kNow + 700, &error)) << error;
  EXPECT_TRUE(restarted.Active("shop.test", kNow + 700));
  EXPECT_FALSE(restarted.Active(AttackSubject{.host = "api.test", .asn = 64500},
                                kNow + 700));
  const std::vector<AttackRecord> history = restarted.History(kNow + 700);
  ASSERT_EQ(history.size(), 3u);
  EXPECT_EQ(history[1].entry.host, "api.test");
  EXPECT_EQ(history[1].entry.threshold, 50);
  EXPECT_EQ(history[1].ended, kNow + 600);
  EXPECT_EQ(history[2].ended, 0);
  std::remove(path.c_str());

  std::ofstream(path) << "[1, 2]";
  AttackMode broken(0, 0, 600, path);
  EXPECT_FALSE(broken.Load(kNow, &error));
  std::remove(path.c_str());
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
  AttackMode attack_{0, 0, 600};
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
  // Browser profiles, for the console's library candidates.
  const nlohmann::json& browsers = body["library"]["browsers"];
  ASSERT_EQ(browsers.size(), 3u);
  EXPECT_EQ(browsers[0]["id"], "chromium");
  EXPECT_EQ(browsers[0]["ja4_ciphers"], nlohmann::json({"8daaf6152771"}));
  EXPECT_EQ(browsers[0]["h2_pseudo_orders"], nlohmann::json({"m,a,s,p"}));
  EXPECT_FALSE(body["crawlers"]["catalog"].empty());
  EXPECT_FALSE(body["model"]["loaded"]);
  // No secrets or paths.
  EXPECT_FALSE(body.contains("captcha_secret_file"));
  EXPECT_FALSE(body["captcha"].contains("site_key"));
  EXPECT_EQ(Call("POST", "/config").status, 405);
}

TEST_F(AdminServerTest, Settings) {
  EXPECT_EQ(Call("GET", "/settings").status, 404);  // Not wired.
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() / "bs_admin_settings";
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  const std::string main = (dir / "bot-shield.yaml").string();
  const std::string layer = (dir / "settings.yaml").string();
  std::ofstream(main) << "admin: {settings_file: " << layer << "}\n"
                      << "events: {token: from-file}\n"
                      << "policy: {thresholds: {bot: 75}}\n";
  SettingsLayer settings(main);
  std::string error;
  ASSERT_TRUE(settings.Load(&config_, false, &error)) << error;
  std::shared_ptr<const VerdictSet> initial;
  ASSERT_TRUE(VerdictSet::Build(config_, &initial, &error)) << error;
  verdicts_.set(initial);
  int published = 0;
  bool build_ok = true;
  context_.settings = &settings;
  context_.apply_settings = [&](const Config& next,
                                const std::function<bool()>& commit,
                                std::string* apply_error) {
    std::shared_ptr<const VerdictSet> set;
    if (!build_ok) {
      *apply_error = "fingerprints: cannot open library";
      return false;
    }
    if (!VerdictSet::Build(next, &set, apply_error) || !commit()) return false;
    verdicts_.set(set);
    ++published;
    return true;
  };

  AdminResponse response = Call("GET", "/settings");
  ASSERT_EQ(response.status, 200);
  EXPECT_TRUE(response.body["editable"]);
  EXPECT_TRUE(response.body["error"].is_null());
  EXPECT_FALSE(response.body["pending_restart"]);
  const std::string revision = response.body["revision"];
  const auto key = [&](const nlohmann::json& body, std::string_view path) {
    for (const auto& item : body["keys"]) {
      if (item["path"] == path) return item;
    }
    return nlohmann::json();
  };
  nlohmann::json bot = key(response.body, "policy.thresholds.bot");
  EXPECT_EQ(bot["value"], 75);
  EXPECT_EQ(bot["default"], 70);
  EXPECT_EQ(bot["source"], "file");
  EXPECT_EQ(bot["apply"], "live");
  EXPECT_EQ(key(response.body, "captcha.rounds")["source"], "default");
  EXPECT_EQ(key(response.body, "captcha.provider")["options"][1], "builtin");
  EXPECT_EQ(key(response.body, "admin.socket")["apply"], "yaml");
  // Secrets: whether they are set, never the value.
  const nlohmann::json token = key(response.body, "events.token");
  EXPECT_TRUE(token["secret"]);
  EXPECT_TRUE(token["set"]);
  EXPECT_FALSE(token.contains("value"));
  EXPECT_FALSE(token.contains("default"));
  EXPECT_EQ(response.body.dump().find("from-file"), std::string::npos);

  // Dry run: a diff, nothing written or published.
  const std::string change =
      R"({"base_revision": ")" + revision +
      R"(", "set": {"policy.thresholds.bot": 80, "captcha.rounds": 3,
          "events.token": "new-token"}})";
  response = Call("POST", "/settings/validate", change);
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(published, 0);
  EXPECT_FALSE(std::filesystem::exists(layer));
  const nlohmann::json& changes = response.body["changes"];
  ASSERT_EQ(changes.size(), 3u);
  EXPECT_EQ(changes[0]["path"], "events.token");
  EXPECT_TRUE(changes[0]["value_changed"]);
  EXPECT_FALSE(changes[0].contains("after"));
  EXPECT_EQ(changes[1]["path"], "policy.thresholds.bot");
  EXPECT_EQ(changes[1]["before"], 75);
  EXPECT_EQ(changes[1]["after"], 80);
  EXPECT_EQ(changes[1]["source_after"], "console");
  EXPECT_EQ(changes[2]["path"], "captcha.rounds");
  EXPECT_TRUE(changes[2]["pending_restart"]);
  EXPECT_EQ(response.body.dump().find("new-token"), std::string::npos);

  // Apply: written, published, restart keys pending.
  response = Call("POST", "/settings", change);
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(published, 1);
  EXPECT_EQ(verdicts_.snapshot()->policy->settings().bot_threshold, 80);
  std::stringstream written;
  written << std::ifstream(layer).rdbuf();
  EXPECT_NE(written.str().find("new-token"), std::string::npos);
  response = Call("GET", "/settings");
  EXPECT_TRUE(response.body["pending_restart"]);
  EXPECT_TRUE(key(response.body, "captcha.rounds")["pending_restart"]);
  EXPECT_FALSE(key(response.body, "policy.thresholds.bot")["pending_restart"]);
  bot = key(response.body, "policy.thresholds.bot");
  EXPECT_EQ(bot["source"], "console");
  EXPECT_EQ(bot["file_value"], 75);
  const std::string applied = response.body["revision"];
  EXPECT_NE(applied, revision);

  // The old revision conflicts; bad values name their key.
  EXPECT_EQ(Call("POST", "/settings", change).status, 409);
  response = Call("POST", "/settings",
                  R"({"base_revision": ")" + applied +
                      R"(", "set": {"policy.thresholds.bot": 10}})");
  EXPECT_EQ(response.status, 422);
  EXPECT_EQ(response.body["path"], "policy.thresholds.bot");
  response = Call("POST", "/settings/validate",
                  R"({"base_revision": ")" + applied +
                      R"(", "set": {"decoy.html_file": "/etc/shadow"}})");
  EXPECT_EQ(response.status, 422);
  EXPECT_EQ(response.body["path"], "decoy.html_file");
  EXPECT_EQ(Call("POST", "/settings", R"({"set": {}})").status, 400);
  EXPECT_EQ(
      Call("POST", "/settings", R"({"base_revision": ")" + applied + R"("})")
          .status,
      400);
  // A verdict set that does not build leaves everything as it was.
  build_ok = false;
  response = Call("POST", "/settings",
                  R"({"base_revision": ")" + applied +
                      R"(", "reset": ["policy.thresholds.bot"]})");
  EXPECT_EQ(response.status, 422);
  EXPECT_EQ(settings.revision(), applied);
  build_ok = true;

  // Reset, history and rollback.
  response = Call("POST", "/settings",
                  R"({"base_revision": ")" + applied +
                      R"(", "reset": ["policy.thresholds.bot"]})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(verdicts_.snapshot()->policy->settings().bot_threshold, 75);
  response = Call("GET", "/settings/history");
  ASSERT_EQ(response.status, 200);
  ASSERT_EQ(response.body["versions"].size(), 2u);
  EXPECT_EQ(response.body["versions"][0]["revision"], applied);
  EXPECT_EQ(response.body["versions"][0]["replaced_at_ms"], kNow * 1000);
  response = Call("POST", "/settings/rollback",
                  R"({"revision": ")" + applied + R"("})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(verdicts_.snapshot()->policy->settings().bot_threshold, 80);
  EXPECT_EQ(settings.revision(), applied);
  EXPECT_EQ(Call("POST", "/settings/rollback", R"({"revision": "x"})").status,
            404);
  EXPECT_EQ(Call("POST", "/settings/rollback", "{}").status, 400);
  EXPECT_EQ(Call("DELETE", "/settings").status, 405);
  EXPECT_EQ(Call("GET", "/settings/nope").status, 404);
  EXPECT_TRUE(Call("GET", "/status").body["settings_error"].is_null());
  std::filesystem::remove_all(dir);
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

  // Extended (a new expiry from now) and re-commented in place.
  const std::string path = "/lists/" + std::to_string(id);
  response = Call("PATCH", path, R"({"ttl":"2h","comment":"still at it"})");
  ASSERT_EQ(response.status, 200) << response.body.dump();
  EXPECT_EQ(response.body["expires_at"], kNow + 7200);
  EXPECT_EQ(response.body["comment"], "still at it");
  EXPECT_EQ(Call("PATCH", path, R"({"kind":"asn"})").status, 400);
  EXPECT_EQ(Call("PATCH", path, "{bad").status, 400);
  EXPECT_EQ(Call("PATCH", "/lists/999", R"({"ttl":60})").status, 404);

  response = Call("POST", "/lists",
                  R"({"kind":"asn","value":"AS14061","action":"block"})");
  ASSERT_EQ(response.status, 201) << response.body.dump();
  EXPECT_EQ(response.body["value"], "14061");
  EXPECT_EQ(Call("DELETE", "/lists/" + response.body["id"].dump()).status, 200);

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
  ASSERT_EQ(response.body["history"].size(), 2u);
  EXPECT_EQ(response.body["history"][0]["host"], "*");
  EXPECT_FALSE(response.body["history"][0].contains("ended"));
  EXPECT_EQ(response.body["auto_rps_total"], 0);
  EXPECT_EQ(Call("GET", "/status").body["attack_entries"], 2);

  // An automatic entry for one network carries its signature.
  std::string error;
  ASSERT_TRUE(attack_.Enable({.host = "api.test",
                              .source = "auto",
                              .since = kNow,
                              .until = kNow + 600,
                              .kind = "ip_prefix",
                              .value = "203.0.113.0/24"},
                             kNow, &error))
      << error;
  response = Call("GET", "/attack");
  ASSERT_EQ(response.body["entries"].size(), 3u);
  EXPECT_EQ(
      response.body["entries"][2]["signature"],
      (nlohmann::json{{"kind", "ip_prefix"}, {"value", "203.0.113.0/24"}}));
  EXPECT_FALSE(response.body["entries"][0].contains("signature"));
  EXPECT_EQ(Call("DELETE", "/attack/api.test").status, 200);

  EXPECT_EQ(Call("POST", "/attack", "{bad").status, 400);
  EXPECT_EQ(Call("POST", "/attack", R"({"host":"a b"})").status, 400);
  EXPECT_EQ(Call("POST", "/attack", R"({"host":"x.test","ttl":"-1s"})").status,
            400);
  EXPECT_EQ(Call("DELETE", "/attack/*").status, 200);
  EXPECT_EQ(Call("DELETE", "/attack/shop.test").status, 200);
  EXPECT_EQ(Call("DELETE", "/attack/shop.test").status, 404);
  EXPECT_FALSE(attack_.Active("shop.test", kNow));
  response = Call("GET", "/attack");
  ASSERT_EQ(response.body["history"].size(), 3u);
  EXPECT_EQ(response.body["history"][0]["ended"], kNow);
  EXPECT_EQ(response.body["history"][0]["signature"]["kind"], "ip_prefix");
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
