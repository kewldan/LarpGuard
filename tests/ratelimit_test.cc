#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "fp/http_request.h"
#include "ratelimit/gcra.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"

namespace bot_shield {
namespace {

constexpr int64_t kSecond = 1'000'000'000;

TEST(GcraTest, BurstThenSustainedRate) {
  // 10 per second, burst 5.
  const GcraParams params = GcraParams::FromRate(10, kSecond, 5);
  EXPECT_EQ(params.emission_ns, kSecond / 10);
  int64_t tat = 0;
  const int64_t start = 100 * kSecond;
  for (int i = 0; i < 5; ++i) {
    const GcraResult result = GcraCheck(&tat, start, params);
    ASSERT_TRUE(result.allowed) << i;
    EXPECT_EQ(result.remaining, 4 - i);
  }
  GcraResult refused = GcraCheck(&tat, start, params);
  EXPECT_FALSE(refused.allowed);
  EXPECT_EQ(refused.retry_after_ns, kSecond / 10);
  // A refused request does not use up capacity.
  refused = GcraCheck(&tat, start + kSecond / 20, params);
  EXPECT_FALSE(refused.allowed);
  EXPECT_TRUE(GcraCheck(&tat, start + kSecond / 10, params).allowed);
  // After a full idle period the burst is available again.
  for (int i = 0; i < 5; ++i) {
    EXPECT_TRUE(GcraCheck(&tat, start + 10 * kSecond, params).allowed);
  }
  EXPECT_FALSE(GcraCheck(&tat, start + 10 * kSecond, params).allowed);
}

TEST(GcraTest, BurstOneSpacesRequests) {
  const GcraParams params = GcraParams::FromRate(1, kSecond, 1);
  EXPECT_EQ(params.tolerance_ns, 0);
  int64_t tat = 0;
  EXPECT_TRUE(GcraCheck(&tat, kSecond, params).allowed);
  EXPECT_FALSE(GcraCheck(&tat, kSecond + kSecond / 2, params).allowed);
  EXPECT_TRUE(GcraCheck(&tat, 2 * kSecond, params).allowed);
}

TEST(RateLimitStoreTest, KeysAreIndependentAndThreadSafe) {
  RateLimitStore store;
  const GcraParams params = GcraParams::FromRate(1000, kSecond, 1000);
  std::atomic<int> allowed{0};
  std::vector<std::thread> threads;
  threads.reserve(8);
  for (int t = 0; t < 8; ++t) {
    threads.emplace_back([&] {
      for (int i = 0; i < 500; ++i) {
        if (store.Check("shared", params, kSecond).allowed) ++allowed;
      }
    });
  }
  for (auto& thread : threads) thread.join();
  // Exactly the burst of a single key, however the threads interleave.
  EXPECT_EQ(allowed.load(), 1000);
  EXPECT_TRUE(store.Check("other", params, kSecond).allowed);
  EXPECT_EQ(store.size(), 2u);
}

TEST(RateLimitStoreTest, FailsOpenWhenFull) {
  RateLimitStore store(64);  // One key per shard.
  const GcraParams params = GcraParams::FromRate(1, kSecond, 1);
  for (int i = 0; i < 1000; ++i) {
    store.Check("k" + std::to_string(i), params, kSecond);
  }
  EXPECT_GT(store.untracked(), 0u);
  EXPECT_LE(store.size(), 64u);
}

TEST(ConnectionCounterTest, AcquireAndRelease) {
  ConnectionCounter counter;
  EXPECT_TRUE(counter.Acquire("1.2.3.4", 2));
  EXPECT_TRUE(counter.Acquire("1.2.3.4", 2));
  EXPECT_FALSE(counter.Acquire("1.2.3.4", 2));
  EXPECT_TRUE(counter.Acquire("5.6.7.8", 2));
  counter.Release("1.2.3.4");
  EXPECT_TRUE(counter.Acquire("1.2.3.4", 2));
  counter.Release("unknown");  // Harmless.
}

TEST(RateLimitsTest, ParseRate) {
  int64_t count = 0;
  std::chrono::milliseconds period{0};
  ASSERT_TRUE(ParseRate("120/m", &count, &period));
  EXPECT_EQ(count, 120);
  EXPECT_EQ(period, std::chrono::minutes(1));
  ASSERT_TRUE(ParseRate("5/s", &count, &period));
  ASSERT_TRUE(ParseRate("1000/d", &count, &period));
  EXPECT_EQ(period, std::chrono::hours(24));
  EXPECT_FALSE(ParseRate("0/s", &count, &period));
  EXPECT_FALSE(ParseRate("5/w", &count, &period));
  EXPECT_FALSE(ParseRate("5", &count, &period));
  EXPECT_FALSE(ParseRate("x/s", &count, &period));
  EXPECT_FALSE(ParseRate("5/ss", &count, &period));
  EXPECT_EQ(RetryAfterSeconds(1), 1);
  EXPECT_EQ(RetryAfterSeconds(kSecond + 1), 2);
}

class RateLimitSetTest : public ::testing::Test {
 protected:
  void SetUp() override {
    http_.method = "POST";
    http_.headers = {{"x-api-key", "k1"}, {"cookie", "a=1; session=s9"}};
    request_.request = &http_;
    request_.ip = asio::ip::make_address("::ffff:203.0.113.7");
    request_.host = "shop.test";
    request_.path = "/login";
    request_.method = "POST";
    request_.bot_class = "human";
    request_.ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
  }

  static RateLimitSpec Spec(std::string name, std::vector<std::string> key,
                            int64_t count, int64_t burst) {
    RateLimitSpec spec;
    spec.name = std::move(name);
    spec.key = std::move(key);
    spec.count = count;
    spec.period = std::chrono::minutes(1);
    spec.burst = burst;
    return spec;
  }

  std::optional<RateLimitHit> Check(const RateLimitSet& limits) {
    return limits.Check(request_, &store_, now_);
  }

  HttpRequest http_;
  RateLimitRequest request_;
  RateLimitStore store_;
  int64_t now_ = 1000 * kSecond;
};

TEST_F(RateLimitSetTest, FiltersAndRefusal) {
  RateLimitSpec login = Spec("login", {"ip"}, 2, 2);
  login.paths = {"/login"};
  login.methods = {"post"};
  login.hosts = {"*.test"};
  login.classes = {"human", "suspicious"};
  RateLimitSet limits;
  std::string error;
  ASSERT_TRUE(RateLimitSet::Compile({login}, &limits, &error)) << error;
  EXPECT_FALSE(Check(limits));
  EXPECT_FALSE(Check(limits));
  const auto hit = Check(limits);
  ASSERT_TRUE(hit);
  EXPECT_EQ(hit->name, "login");
  EXPECT_EQ(hit->burst, 2);
  EXPECT_EQ(hit->window_seconds, 60);
  EXPECT_GT(hit->result.retry_after_ns, 0);

  // Other paths, methods, hosts or classes are not counted.
  request_.path = "/";
  EXPECT_FALSE(Check(limits));
  request_.path = "/login";
  request_.method = "GET";
  EXPECT_FALSE(Check(limits));
  request_.method = "POST";
  request_.bot_class = "bot";
  EXPECT_FALSE(Check(limits));
  request_.bot_class = "human";
  request_.host = "shop.other";
  EXPECT_FALSE(Check(limits));
}

TEST_F(RateLimitSetTest, KeysSeparateClientsAndSkipMissingParts) {
  RateLimitSet limits;
  std::string error;
  ASSERT_TRUE(
      RateLimitSet::Compile({Spec("api", {"header:X-Api-Key"}, 1, 1),
                             Spec("session", {"cookie:session", "host"}, 1, 1),
                             Spec("prefix", {"ip_prefix", "fp"}, 100, 100)},
                            &limits, &error))
      << error;
  EXPECT_FALSE(Check(limits));
  const auto hit = Check(limits);
  ASSERT_TRUE(hit);
  EXPECT_EQ(hit->name, "api");  // First refusing limit is reported.

  // Another API key and session: a fresh bucket.
  http_.headers = {{"x-api-key", "k2"}, {"cookie", "session=other"}};
  EXPECT_FALSE(Check(limits));
  // No key and no session cookie: those limits do not apply at all.
  http_.headers.clear();
  for (int i = 0; i < 5; ++i) EXPECT_FALSE(Check(limits));
}

TEST_F(RateLimitSetTest, IpKeysUnmapIpv4) {
  RateLimitSet limits;
  std::string error;
  ASSERT_TRUE(
      RateLimitSet::Compile({Spec("ip", {"ip"}, 1, 1)}, &limits, &error));
  EXPECT_FALSE(Check(limits));
  request_.ip = asio::ip::make_address("203.0.113.7");  // Same client.
  EXPECT_TRUE(Check(limits));
}

TEST_F(RateLimitSetTest, Validation) {
  RateLimitSet limits;
  std::string error;
  EXPECT_FALSE(
      RateLimitSet::Compile({Spec("", {"ip"}, 1, 1)}, &limits, &error));
  EXPECT_FALSE(RateLimitSet::Compile(
      {Spec("a", {"ip"}, 1, 1), Spec("a", {"ip"}, 1, 1)}, &limits, &error));
  EXPECT_FALSE(RateLimitSet::Compile({Spec("a", {}, 1, 1)}, &limits, &error));
  EXPECT_FALSE(
      RateLimitSet::Compile({Spec("a", {"mac"}, 1, 1)}, &limits, &error));
  EXPECT_FALSE(
      RateLimitSet::Compile({Spec("a", {"header:"}, 1, 1)}, &limits, &error));
  EXPECT_FALSE(
      RateLimitSet::Compile({Spec("a", {"ip"}, 1, 0)}, &limits, &error));
  RateLimitSpec bad_class = Spec("a", {"ip"}, 1, 1);
  bad_class.classes = {"robot"};
  EXPECT_FALSE(RateLimitSet::Compile({bad_class}, &limits, &error));
  EXPECT_NE(error.find("unknown class 'robot'"), std::string::npos) << error;
}

}  // namespace
}  // namespace bot_shield
