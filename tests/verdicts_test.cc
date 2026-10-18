#include "server/verdicts.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "challenge/challenger.h"
#include "challenge/token.h"
#include "config/config.h"
#include "fp/http_request.h"
#include "score/policy.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

TEST(VerdictSetTest, BuildsFromConfig) {
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(R"(
policy: {thresholds: {suspicious: 20, bot: 60}, hosts: {shop.test: enforce}}
rules:
  - {name: admin, when: 'path ~ "/admin*"', action: block}
rate_limits:
  - {name: login, key: [ip], rate: 5/m}
throttle: {rate: 10/m, burst: 2}
crawlers: {ai: block}
honeypot: {paths: [/trap]}
)",
                          &config, &error))
      << error;
  std::shared_ptr<const VerdictSet> set;
  ASSERT_TRUE(VerdictSet::Build(config, &set, &error)) << error;
  EXPECT_EQ(set->scorer->Classify(25), BotClass::kSuspicious);
  EXPECT_EQ(set->policy->ModeFor("shop.test"), HostMode::kEnforce);
  EXPECT_FALSE(set->rules.empty());
  EXPECT_FALSE(set->rate_limits.empty());
  EXPECT_FALSE(set->throttle.empty());
  EXPECT_EQ(set->ai_crawler_action, Action::kBlock);
  EXPECT_EQ(set->honeypot_paths, (std::vector<std::string>{"/trap"}));
  EXPECT_EQ(set->model, nullptr);
  EXPECT_GT(set->library->profile_count(), 0u);

  config.fingerprint_library = "/nonexistent/fingerprints.yaml";
  EXPECT_FALSE(VerdictSet::Build(config, &set, &error));
  EXPECT_NE(error.find("fingerprints"), std::string::npos);
  config.fingerprint_library.clear();
  config.model_file = "/nonexistent/model.json";
  EXPECT_FALSE(VerdictSet::Build(config, &set, &error));
  EXPECT_NE(error.find("model"), std::string::npos);
}

TEST(VerdictSetTest, StoreNumbersGenerations) {
  VerdictStore store;
  EXPECT_EQ(store.snapshot(), nullptr);
  std::shared_ptr<const VerdictSet> set;
  std::string error;
  ASSERT_TRUE(VerdictSet::Build(Config(), &set, &error)) << error;
  store.set(set);
  const auto first = store.snapshot();
  EXPECT_EQ(first->generation, 1u);
  store.set(set);
  EXPECT_EQ(store.snapshot()->generation, 2u);
  EXPECT_EQ(first->generation, 1u);  // Old snapshots stay as they were.
}

TEST(VerdictSetTest, ParsesThrottleAction) {
  Config config;
  std::string error;
  ASSERT_TRUE(
      ParseConfig("policy: {actions: {suspicious: throttle}}\n"
                  "throttle: {rate: 30/m, key: [session]}\n",
                  &config, &error))
      << error;
  EXPECT_EQ(config.policy.suspicious_action, Action::kThrottle);
  ASSERT_TRUE(config.throttle.has_value());
  EXPECT_EQ(config.throttle->key, (std::vector<std::string>{"session"}));
  EXPECT_EQ(config.throttle->burst, 30);
  Config defaults;
  ASSERT_TRUE(ParseConfig("throttle: {rate: 1/s}\n", &defaults, &error));
  ASSERT_TRUE(defaults.throttle.has_value());
  EXPECT_EQ(defaults.throttle->key,
            (std::vector<std::string>{"ip_prefix", "ja4"}));
  Config bad;
  EXPECT_FALSE(ParseConfig("throttle: {burst: 3}\n", &bad, &error));
  EXPECT_FALSE(
      ParseConfig("throttle: {rate: 1/s, key: [mac]}\n", &bad, &error));
  EXPECT_FALSE(
      ParseConfig("throttle: {rate: 1/s, paths: [/]}\n", &bad, &error));
}

TEST(SessionIdTest, IdentifiesValidTokens) {
  ChallengeSettings settings;
  settings.keys = TokenKeys::Random();
  const ChallengeSettings copy = settings;
  const Challenger challenger(settings);
  const int64_t now = 1'800'000'000;
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  TokenClaims claims;
  claims.issued = now;
  claims.expires = now + 600;
  claims.binding = binding;
  const std::string token = IssueToken(copy.keys, claims);
  HttpRequest request;
  request.headers = {{"cookie", "__bs=" + token}};
  const auto session = challenger.SessionId(request, binding, now);
  ASSERT_TRUE(session.has_value());
  EXPECT_EQ(session->size(), 16u);
  EXPECT_EQ(challenger.SessionId(request, binding, now), session);
  EXPECT_FALSE(challenger.SessionId(request, binding, now + 601));
  EXPECT_FALSE(challenger.SessionId(HttpRequest(), binding, now));
  claims.issued = now + 1;
  request.headers = {{"cookie", "__bs=" + IssueToken(copy.keys, claims)}};
  EXPECT_NE(challenger.SessionId(request, binding, now), session);
}

}  // namespace
}  // namespace bot_shield
