#include "behavior/behavior.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "config/config.h"

namespace bot_shield {
namespace {

bool Has(const std::vector<std::string>& signals, const std::string& name) {
  return std::ranges::find(signals, name) != signals.end();
}

RequestFacts Navigation(std::string_view path) {
  return ClassifyRequest("GET", path, "navigate", "document", "text/html", "");
}

TEST(ClassifyRequestTest, SortsRequests) {
  EXPECT_TRUE(Navigation("/").navigation);
  EXPECT_TRUE(
      ClassifyRequest("GET", "/", "", "", "text/html,*/*", "").navigation);
  EXPECT_TRUE(ClassifyRequest("GET", "/app.js", "", "", "*/*", "").asset);
  EXPECT_TRUE(
      ClassifyRequest("GET", "/img", "no-cors", "image", "image/*", "").asset);
  EXPECT_TRUE(
      ClassifyRequest("GET", "/x", "cors", "empty", "application/json", "")
          .api);
  EXPECT_TRUE(ClassifyRequest("POST", "/api/cart", "", "", "*/*", "").api);
  EXPECT_TRUE(
      ClassifyRequest("GET", "/x", "", "", "*/*", "XMLHttpRequest").api);
  const RequestFacts plain = ClassifyRequest("GET", "/x", "", "", "*/*", "");
  EXPECT_FALSE(plain.navigation || plain.api || plain.asset);
}

TEST(BehaviorStoreTest, RegularTiming) {
  BehaviorStore store;
  std::vector<std::string> signals;
  for (int i = 0; i < 16; ++i) {
    signals.clear();
    store.OnRequest("c", "h", Navigation("/p"), 1000 + i * 2000, &signals);
  }
  EXPECT_TRUE(Has(signals, "behavior_regular_timing"));

  // Jittery timing: no signal.
  const int64_t jitter[] = {0,     700,   3100,  3500,  7000,  7300,
                            9900,  13000, 13200, 16800, 17100, 20500,
                            22000, 22300, 26000, 27100};
  for (const int64_t at : jitter) {
    signals.clear();
    store.OnRequest("human", "h", Navigation("/p"), at, &signals);
  }
  EXPECT_FALSE(Has(signals, "behavior_regular_timing"));
}

TEST(BehaviorStoreTest, NotFoundAndApiWithoutPage) {
  BehaviorStore store;
  std::vector<std::string> signals;
  for (int i = 0; i < 20; ++i) {
    signals.clear();
    store.OnRequest(
        "scanner", "h",
        ClassifyRequest("GET", std::format("/x{}", i), "", "", "*/*", ""),
        i * 137 + (i % 3) * 51, &signals);
    store.OnStatus("scanner", i % 4 == 0 ? 200 : 404, 0);
  }
  signals.clear();
  store.OnRequest("scanner", "h",
                  ClassifyRequest("GET", "/y", "", "", "*/*", ""), 5000,
                  &signals);
  EXPECT_TRUE(Has(signals, "behavior_not_found"));

  for (int i = 0; i < 10; ++i) {
    signals.clear();
    store.OnRequest("api", "h",
                    ClassifyRequest("GET", "/api/items", "cors", "empty",
                                    "application/json", ""),
                    i * 333 + (i % 2) * 90, &signals);
  }
  EXPECT_TRUE(Has(signals, "behavior_api_without_page"));
  // A browser that loaded a page first is fine.
  store.OnRequest("spa", "h", Navigation("/"), 0, &signals);
  for (int i = 0; i < 12; ++i) {
    signals.clear();
    store.OnRequest("spa", "h",
                    ClassifyRequest("GET", "/api/items", "cors", "empty",
                                    "application/json", ""),
                    100 + i * 333 + (i % 2) * 90, &signals);
  }
  EXPECT_FALSE(Has(signals, "behavior_api_without_page"));
}

TEST(BehaviorStoreTest, NoAssetsOnlyWhereAssetsGoThroughTheGateway) {
  BehaviorStore store;
  std::vector<std::string> signals;
  for (int i = 0; i < 10; ++i) {
    signals.clear();
    store.OnRequest("c", "static-elsewhere", Navigation("/p"),
                    i * 1000 + (i % 3) * 200, &signals);
  }
  EXPECT_FALSE(Has(signals, "behavior_no_assets"));

  // Another client loads assets on "shop": the host serves them here.
  store.OnRequest(
      "browser", "shop",
      ClassifyRequest("GET", "/app.css", "no-cors", "style", "text/css", ""), 0,
      &signals);
  for (int i = 0; i < 10; ++i) {
    signals.clear();
    store.OnRequest("bot", "shop", Navigation(std::format("/p{}", i)),
                    i * 1000 + (i % 3) * 200, &signals);
  }
  EXPECT_TRUE(Has(signals, "behavior_no_assets"));
}

TEST(BehaviorStoreTest, SequentialIds) {
  BehaviorStore store;
  std::vector<std::string> signals;
  for (int id = 100; id < 111; ++id) {
    signals.clear();
    store.OnRequest("c", "h", Navigation(std::format("/item/{}/", id)),
                    id * 977 + (id % 3) * 300, &signals);
  }
  EXPECT_TRUE(Has(signals, "behavior_sequential_ids"));
  // Another pattern starts over.
  signals.clear();
  store.OnRequest("c", "h", Navigation("/user/7"), 200000, &signals);
  EXPECT_FALSE(Has(signals, "behavior_sequential_ids"));
}

TEST(BehaviorStoreTest, WindowStartsOver) {
  BehaviorSettings settings;
  settings.window = std::chrono::seconds(10);
  BehaviorStore store(settings);
  std::vector<std::string> signals;
  for (int i = 0; i < 16; ++i) {
    signals.clear();
    store.OnRequest("c", "h", Navigation("/p"), int64_t{i} * 500, &signals);
  }
  EXPECT_TRUE(Has(signals, "behavior_regular_timing"));
  signals.clear();
  store.OnRequest("c", "h", Navigation("/p"), 60'000, &signals);
  EXPECT_TRUE(signals.empty());
}

TEST(BehaviorStoreTest, Traps) {
  BehaviorStore store;
  const std::vector<std::string> keys = {"ip|192.0.2.1", "fp|aa|bb"};
  EXPECT_FALSE(store.Trapped(keys, 0));
  store.Trap(keys, 0, 1000);
  EXPECT_TRUE(store.Trapped({"ip|192.0.2.1"}, 999));
  EXPECT_TRUE(store.Trapped({"ip|192.0.2.9", "fp|aa|bb"}, 999));
  EXPECT_FALSE(store.Trapped(keys, 1000));
  EXPECT_FALSE(store.Trapped({"ip|192.0.2.9"}, 10));
}

TEST(BehaviorStoreTest, BoundedMemory) {
  BehaviorSettings settings;
  settings.max_clients = 64;  // One per shard.
  BehaviorStore store(settings);
  std::vector<std::string> signals;
  for (int i = 0; i < 1000; ++i) {
    store.OnRequest(std::format("c{}", i), "h", Navigation("/"), 0, &signals);
  }
  EXPECT_LE(store.size(), 64U);
  EXPECT_GT(store.untracked(), 0U);
}

TEST(BehaviorConfigTest, ParsesBehaviorAndHoneypot) {
  Config config;
  std::string error;
  EXPECT_TRUE(config.behavior_enabled);
  EXPECT_FALSE(config.honeypot_paths.empty());
  ASSERT_TRUE(
      ParseConfig("behavior: {enabled: false, window: 5m, max_clients: 1000}\n"
                  "honeypot: {paths: [/trap, \"/old-admin/*\"], ttl: 30m}\n",
                  &config, &error))
      << error;
  EXPECT_FALSE(config.behavior_enabled);
  EXPECT_EQ(config.behavior_window, std::chrono::minutes(5));
  EXPECT_EQ(config.behavior_max_clients, 1000U);
  EXPECT_EQ(config.honeypot_paths,
            (std::vector<std::string>{"/trap", "/old-admin/*"}));
  EXPECT_EQ(config.honeypot_ttl, std::chrono::minutes(30));

  Config bad;
  EXPECT_FALSE(ParseConfig("honeypot: {paths: [trap]}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("honeypot: {paths: /trap}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("behavior: {window: 1s}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("behavior: {rps: 1}\n", &bad, &error));
}

}  // namespace
}  // namespace bot_shield
