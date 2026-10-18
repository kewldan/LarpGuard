#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <atomic>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "config/config.h"
#include "crawler/crawlers.h"
#include "crawler/verifier.h"
#include "score/policy.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

constexpr int64_t kNow = 1'800'000'000;

TEST(CrawlersTest, FindsCrawlersByUserAgent) {
  const auto id = [](std::string_view user_agent) -> std::string {
    const KnownCrawler* crawler = FindCrawler(user_agent);
    return crawler == nullptr ? "" : std::string(crawler->id);
  };
  EXPECT_EQ(id("Mozilla/5.0 (compatible; Googlebot/2.1; "
               "+http://www.google.com/bot.html)"),
            "google");
  EXPECT_EQ(id("Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) "
               "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 "
               "Mobile Safari/537.36 (compatible; Googlebot/2.1)"),
            "google");
  EXPECT_EQ(id("Mozilla/5.0 (compatible; bingbot/2.0; "
               "+http://www.bing.com/bingbot.htm)"),
            "bing");
  EXPECT_EQ(id("Mozilla/5.0 (compatible; YandexBot/3.0; "
               "+http://yandex.com/bots)"),
            "yandex");
  EXPECT_EQ(id("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; "
               "compatible; GPTBot/1.2; +https://openai.com/gptbot)"),
            "openai");
  EXPECT_EQ(id("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; "
               "compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"),
            "anthropic");
  EXPECT_EQ(id("CCBot/2.0 (https://commoncrawl.org/faq/)"), "commoncrawl");
  EXPECT_EQ(id("meta-externalagent/1.1"), "meta");
  EXPECT_EQ(id("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
               "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 "
               "YaBrowser/25.8.0.0 Safari/537.36"),
            "");
  EXPECT_EQ(id("curl/8.7.1"), "");
  EXPECT_EQ(id(""), "");

  const KnownCrawler* google = FindCrawler("Googlebot/2.1");
  ASSERT_NE(google, nullptr);
  EXPECT_FALSE(google->ai);
  EXPECT_FALSE(google->domains.empty());
  const KnownCrawler* openai = FindCrawler("GPTBot/1.2");
  ASSERT_NE(openai, nullptr);
  EXPECT_TRUE(openai->ai);
  EXPECT_TRUE(openai->domains.empty());
}

TEST(CrawlersTest, MatchesDomainsBySuffixOnly) {
  const std::vector<std::string_view> domains = {"googlebot.com", "google.com"};
  EXPECT_TRUE(HostnameInDomains("crawl-66-249-66-1.googlebot.com", domains));
  EXPECT_TRUE(HostnameInDomains("rate-limited-proxy-66-249-90-77.google.com.",
                                domains));
  EXPECT_TRUE(HostnameInDomains("CRAWL-1.GOOGLEBOT.COM", domains));
  EXPECT_TRUE(HostnameInDomains("google.com", domains));
  EXPECT_FALSE(HostnameInDomains("evilgooglebot.com", domains));
  EXPECT_FALSE(HostnameInDomains("googlebot.com.evil.test", domains));
  EXPECT_FALSE(HostnameInDomains("", domains));
}

// Fake DNS: PTR and A records from maps, counting lookups.
struct FakeDns {
  std::map<std::string, std::string> ptr;
  std::map<std::string, std::vector<std::string>> a;
  std::atomic<int> reverse_lookups{0};

  CrawlerVerifier::Resolver Resolver() {
    CrawlerVerifier::Resolver resolver;
    resolver.reverse = [this](const asio::ip::address& ip) {
      ++reverse_lookups;
      const auto it = ptr.find(ip.to_string());
      return it == ptr.end() ? std::string() : it->second;
    };
    resolver.forward = [this](const std::string& name) {
      std::vector<asio::ip::address> out;
      if (const auto it = a.find(name); it != a.end()) {
        for (const std::string& ip : it->second) {
          out.push_back(asio::ip::make_address(ip));
        }
      }
      return out;
    };
    return resolver;
  }
};

TEST(CrawlerVerifierTest, VerifiesWithReverseAndForwardLookups) {
  FakeDns dns;
  dns.ptr["66.249.66.1"] = "crawl-66-249-66-1.googlebot.com.";
  dns.a["crawl-66-249-66-1.googlebot.com."] = {"66.249.66.1"};
  // PTR in the right domain, but the name does not resolve back.
  dns.ptr["203.0.113.5"] = "crawl-1.googlebot.com";
  dns.a["crawl-1.googlebot.com"] = {"66.249.66.9"};
  // Wrong domain.
  dns.ptr["198.51.100.7"] = "host.evil.test";
  dns.a["host.evil.test"] = {"198.51.100.7"};

  CrawlerVerifier verifier(dns.Resolver(), CrawlerVerifier::Settings());
  const KnownCrawler& google = *FindCrawler("Googlebot/2.1");
  const auto check = [&](std::string_view ip) {
    return verifier.Check(google, asio::ip::make_address(ip), kNow);
  };
  EXPECT_EQ(check("66.249.66.1"), CrawlerStatus::kPending);
  EXPECT_EQ(check("203.0.113.5"), CrawlerStatus::kPending);
  EXPECT_EQ(check("198.51.100.7"), CrawlerStatus::kPending);
  EXPECT_EQ(check("192.0.2.1"), CrawlerStatus::kPending);  // No PTR.
  verifier.WaitIdle();
  EXPECT_EQ(check("66.249.66.1"), CrawlerStatus::kVerified);
  EXPECT_EQ(check("::ffff:66.249.66.1"), CrawlerStatus::kVerified);
  EXPECT_EQ(check("203.0.113.5"), CrawlerStatus::kFailed);
  EXPECT_EQ(check("198.51.100.7"), CrawlerStatus::kFailed);
  EXPECT_EQ(check("192.0.2.1"), CrawlerStatus::kFailed);
  EXPECT_EQ(dns.reverse_lookups.load(), 4);  // Cached.

  // The same address claiming another crawler is checked separately.
  EXPECT_EQ(verifier.Check(*FindCrawler("bingbot/2.0"),
                           asio::ip::make_address("66.249.66.1"), kNow),
            CrawlerStatus::kPending);
  verifier.WaitIdle();
  EXPECT_EQ(verifier.Check(*FindCrawler("bingbot/2.0"),
                           asio::ip::make_address("66.249.66.1"), kNow),
            CrawlerStatus::kFailed);

  // Entries expire.
  EXPECT_EQ(check("66.249.66.1"), CrawlerStatus::kVerified);
  const int64_t later = kNow + 10LL * 365 * 24 * 3600;
  EXPECT_EQ(
      verifier.Check(google, asio::ip::make_address("66.249.66.1"), later),
      CrawlerStatus::kPending);
}

TEST(CrawlerVerifierTest, BoundsTheQueue) {
  FakeDns dns;
  CrawlerVerifier::Settings settings;
  settings.max_queue = 0;
  CrawlerVerifier verifier(dns.Resolver(), settings);
  const KnownCrawler& google = *FindCrawler("Googlebot/2.1");
  EXPECT_EQ(verifier.Check(google, asio::ip::make_address("192.0.2.1"), kNow),
            CrawlerStatus::kPending);
  verifier.WaitIdle();
  EXPECT_EQ(dns.reverse_lookups.load(), 0);
}

TEST(CrawlerPolicyTest, VerifiedBotsHaveTheirOwnAction) {
  PolicySettings settings;
  settings.verified_bot_action = Action::kChallenge;
  const Policy policy(settings);
  Verdict verdict;
  verdict.bot_class = BotClass::kVerifiedBot;
  EXPECT_EQ(policy.Decide(verdict, HostMode::kEnforce).action,
            Action::kChallenge);
  EXPECT_EQ(BotClassName(BotClass::kVerifiedBot), "verified_bot");
}

TEST(CrawlerConfigTest, ParsesCrawlers) {
  Config config;
  std::string error;
  EXPECT_TRUE(config.crawlers_verify);
  EXPECT_FALSE(config.crawlers_ai.has_value());
  ASSERT_TRUE(ParseConfig(
      "crawlers: {verify: false, ai: block}\n"
      "policy: {actions: {verified_bot: challenge}}\n"
      "rate_limits:\n"
      "  - {name: crawlers, classes: [verified_bot], key: [ip], rate: 5/s}\n",
      &config, &error))
      << error;
  EXPECT_FALSE(config.crawlers_verify);
  EXPECT_EQ(config.crawlers_ai, Action::kBlock);
  EXPECT_EQ(config.policy.verified_bot_action, Action::kChallenge);

  Config fresh;
  ASSERT_TRUE(ParseConfig("crawlers: {ai: default}\n", &fresh, &error));
  EXPECT_FALSE(fresh.crawlers_ai.has_value());
  Config bad;
  EXPECT_FALSE(ParseConfig("crawlers: {ai: captcha}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("crawlers: {rdns: true}\n", &bad, &error));
}

}  // namespace
}  // namespace bot_shield
