#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "fp/http_request.h"
#include "fp/library.h"
#include "fp/user_agent.h"
#include "score/policy.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

constexpr char kChromeUa[] =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
constexpr char kFirefoxUa[] =
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0";
constexpr char kSafariUa[] =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Safari/605.1.15";
constexpr char kChromeJa4[] = "t13d1516h2_8daaf6152771_02713d6af862";
constexpr char kCurlJa4[] = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac";

// --- User-Agent -------------------------------------------------------------

TEST(UserAgentTest, Browsers) {
  UserAgent ua = ParseUserAgent(kChromeUa);
  EXPECT_EQ(ua.family, "chrome");
  EXPECT_EQ(ua.engine, "chromium");
  EXPECT_EQ(ua.major, 131);
  EXPECT_EQ(ua.os, "windows");
  EXPECT_TRUE(ua.tool.empty());

  ua = ParseUserAgent(kFirefoxUa);
  EXPECT_EQ(ua.engine, "firefox");
  EXPECT_EQ(ua.major, 133);
  EXPECT_EQ(ua.os, "linux");

  ua = ParseUserAgent(kSafariUa);
  EXPECT_EQ(ua.family, "safari");
  EXPECT_EQ(ua.engine, "webkit");
  EXPECT_EQ(ua.major, 18);
  EXPECT_EQ(ua.os, "macos");

  ua = ParseUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
      "like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0");
  EXPECT_EQ(ua.family, "edge");
  EXPECT_EQ(ua.engine, "chromium");

  // Chrome on iOS runs on WebKit.
  ua = ParseUserAgent(
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 Mobile/15E148 "
      "Safari/604.1");
  EXPECT_EQ(ua.family, "chrome");
  EXPECT_EQ(ua.engine, "webkit");
  EXPECT_EQ(ua.os, "ios");
  EXPECT_TRUE(ua.mobile);
}

TEST(UserAgentTest, ToolsHeadlessAndCrawlers) {
  EXPECT_EQ(ParseUserAgent("curl/8.7.1").tool, "curl");
  EXPECT_EQ(ParseUserAgent("python-requests/2.32.3").tool, "python-requests");
  EXPECT_EQ(ParseUserAgent("Go-http-client/2.0").tool, "go-http-client");
  EXPECT_TRUE(ParseUserAgent("curl/8.7.1").engine.empty());

  const UserAgent headless = ParseUserAgent(
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
      "Gecko) HeadlessChrome/131.0.0.0 Safari/537.36");
  EXPECT_TRUE(headless.headless);
  EXPECT_EQ(headless.engine, "chromium");

  EXPECT_TRUE(ParseUserAgent("Mozilla/5.0 (compatible; Googlebot/2.1; "
                             "+http://www.google.com/bot.html)")
                  .claims_crawler);
  // A phone model, not a crawler.
  EXPECT_FALSE(ParseUserAgent("Mozilla/5.0 (Linux; Android 12; CUBOT X50) "
                              "AppleWebKit/537.36 Chrome/120.0 Mobile")
                   .claims_crawler);
  EXPECT_TRUE(ParseUserAgent("").family.empty());
}

// --- Library ----------------------------------------------------------------

TEST(LibraryTest, BuiltInMatchesDeployFile) {
  std::ifstream file(std::string(BOT_SHIELD_SOURCE_DIR) +
                     "/deploy/fingerprints.yaml");
  ASSERT_TRUE(file) << "deploy/fingerprints.yaml not found";
  std::stringstream contents;
  contents << file.rdbuf();
  EXPECT_EQ(contents.str(), FingerprintLibrary::BuiltInYaml())
      << "src/fp/library.cc embeds a different copy of the library";
  const FingerprintLibrary& library = FingerprintLibrary::BuiltIn();
  EXPECT_EQ(library.profile_count(), 3u);
  ASSERT_NE(library.ProfileForEngine("chromium"), nullptr);
  EXPECT_EQ(library.ProfileForEngine("chromium")->ja4_ciphers,
            std::vector<std::string>{"8daaf6152771"});
  EXPECT_EQ(library.ProfileForEngine("nope"), nullptr);
  EXPECT_EQ(library.Weight("ua_tls_mismatch"), 45);
  EXPECT_EQ(library.Weight("unknown"), 0);
}

TEST(LibraryTest, ParsesAutomationAndRejectsBadEntries) {
  FingerprintLibrary library;
  std::string error;
  ASSERT_TRUE(FingerprintLibrary::Parse(R"(
browsers: []
automation:
  - {id: scraper, weight: 60, ja4: "t13d3112*", user_agent: "Mozilla"}
weights: {}
)",
                                        &library, &error))
      << error;
  ASSERT_EQ(library.automation().size(), 1u);
  EXPECT_EQ(library.automation()[0].user_agent, "mozilla");
  EXPECT_FALSE(FingerprintLibrary::Parse("automation: [{id: x, weight: 5}]",
                                         &library, &error));
  EXPECT_FALSE(
      FingerprintLibrary::Parse("browsers: [{id: x}]", &library, &error));
  EXPECT_FALSE(FingerprintLibrary::Parse("[1, 2", &library, &error));
}

TEST(LibraryTest, Glob) {
  EXPECT_TRUE(GlobMatch("t13d*_8daaf6152771_*", kChromeJa4));
  EXPECT_FALSE(GlobMatch("t12*", kChromeJa4));
  EXPECT_TRUE(GlobMatch("*", ""));
  EXPECT_TRUE(GlobMatch("a*b*c", "aXXbYYc"));
  EXPECT_FALSE(GlobMatch("a*b*c", "aXXbYY"));
  EXPECT_TRUE(GlobMatch("exact", "exact"));
}

// --- Scorer -----------------------------------------------------------------

HttpRequest BrowserRequest(const char* user_agent) {
  HttpRequest request;
  request.version = "2";
  request.method = "GET";
  request.headers = {{"user-agent", user_agent},
                     {"sec-ch-ua", R"("Chromium";v="131")"},
                     {"sec-fetch-mode", "navigate"},
                     {"accept-language", "en-US,en;q=0.9"}};
  return request;
}

class ScorerTest : public ::testing::Test {
 protected:
  Verdict Score(const HttpRequest& request, std::string_view ja4,
                std::string_view pseudo = "m,a,s,p", bool offered_h2 = true,
                int ttl = 0) const {
    ScoringInput input;
    input.request = &request;
    input.ja4 = ja4;
    input.offered_h2 = offered_h2;
    input.pseudo_order = pseudo;
    input.tcp_initial_ttl = ttl;
    return scorer_.Score(input);
  }

  static bool Has(const Verdict& verdict, std::string_view reason) {
    return std::ranges::find(verdict.reasons, reason) != verdict.reasons.end();
  }

  Scorer scorer_{&FingerprintLibrary::BuiltIn(), 30, 70};
};

TEST_F(ScorerTest, ConsistentChromeIsHuman) {
  const Verdict verdict = Score(BrowserRequest(kChromeUa), kChromeJa4);
  EXPECT_EQ(verdict.score, 0);
  EXPECT_EQ(verdict.bot_class, BotClass::kHuman);
  EXPECT_TRUE(verdict.reasons.empty());
}

TEST_F(ScorerTest, CurlIsBot) {
  HttpRequest request;
  request.headers = {{"user-agent", "curl/8.7.1"}};
  const Verdict verdict = Score(request, kCurlJa4, "m,s,a,p");
  EXPECT_EQ(verdict.bot_class, BotClass::kBot);
  EXPECT_TRUE(Has(verdict, "automation_user_agent"));
}

TEST_F(ScorerTest, SpoofedChromeUserAgentIsCaught) {
  // A library client with a copied Chrome User-Agent and headers.
  const Verdict verdict =
      Score(BrowserRequest(kChromeUa), kCurlJa4, "m,p,s,a", true);
  EXPECT_TRUE(Has(verdict, "ua_tls_mismatch"));
  EXPECT_TRUE(Has(verdict, "ua_h2_mismatch"));
  EXPECT_EQ(verdict.score, 80);
  EXPECT_EQ(verdict.bot_class, BotClass::kBot);
}

TEST_F(ScorerTest, MissingBrowserHeadersAndHttp1Only) {
  HttpRequest request;
  request.version = "1.1";
  request.headers = {{"user-agent", kChromeUa}};
  const Verdict verdict = Score(request, kChromeJa4, "", false);
  EXPECT_TRUE(Has(verdict, "browser_without_h2"));
  EXPECT_TRUE(Has(verdict, "missing_client_hints"));
  EXPECT_TRUE(Has(verdict, "missing_fetch_metadata"));
  EXPECT_TRUE(Has(verdict, "missing_accept_language"));
  EXPECT_EQ(verdict.score, 90);
}

TEST_F(ScorerTest, FirefoxDoesNotNeedClientHints) {
  HttpRequest request = BrowserRequest(kFirefoxUa);
  request.headers.erase(request.headers.begin() + 1);  // sec-ch-ua
  const Verdict verdict =
      Score(request, "t13d1715h2_5b57614c22b0_3d5424432f57", "m,p,a,s");
  EXPECT_EQ(verdict.score, 0) << verdict.reasons.size();
}

TEST_F(ScorerTest, TcpOsMismatch) {
  // Windows User-Agent from a stack that starts TTLs at 64.
  const Verdict verdict =
      Score(BrowserRequest(kChromeUa), kChromeJa4, "m,a,s,p", true, 64);
  EXPECT_TRUE(Has(verdict, "os_tcp_mismatch"));
  EXPECT_EQ(
      Score(BrowserRequest(kChromeUa), kChromeJa4, "m,a,s,p", true, 128).score,
      0);
}

TEST(RelayTest, HandshakeFarSlowerThanTcpLooksRelayed) {
  // A proxy 5 ms away, the client 150 ms behind it.
  EXPECT_TRUE(LooksRelayed(5'000, 155'000));
  // A distant client without a relay: the two agree.
  EXPECT_FALSE(LooksRelayed(140'000, 150'000));
  // A slow phone adds a few tens of milliseconds: below the gap.
  EXPECT_FALSE(LooksRelayed(20'000, 70'000));
  // Large gap but not three times the TCP round trip.
  EXPECT_FALSE(LooksRelayed(60'000, 170'000));
  EXPECT_TRUE(LooksRelayed(40'000, 120'000));
  // Unknown either way.
  EXPECT_FALSE(LooksRelayed(-1, 200'000));
  EXPECT_FALSE(LooksRelayed(5'000, -1));
  EXPECT_FALSE(LooksRelayed(0, 200'000));
}

TEST_F(ScorerTest, RelayedConnectionSignal) {
  const HttpRequest request = BrowserRequest(kChromeUa);
  ScoringInput input;
  input.request = &request;
  input.ja4 = kChromeJa4;
  input.offered_h2 = true;
  input.pseudo_order = "m,a,s,p";
  input.tcp_rtt_us = 4'000;
  input.handshake_us = 180'000;
  const Verdict relayed = scorer_.Score(input);
  EXPECT_TRUE(Has(relayed, "relayed_connection"));
  EXPECT_EQ(relayed.score,
            FingerprintLibrary::BuiltIn().Weight("relayed_connection"));
  input.handshake_us = 9'000;
  EXPECT_FALSE(Has(scorer_.Score(input), "relayed_connection"));
}

TEST_F(ScorerTest, AutomationSignaturesAndCap) {
  FingerprintLibrary library;
  std::string error;
  ASSERT_TRUE(FingerprintLibrary::Parse(R"(
browsers: []
automation:
  - {id: a, weight: 70, ja4: "t13d3112*"}
  - {id: b, weight: 70, user_agent: "MOZILLA"}
weights: {}
)",
                                        &library, &error));
  const Scorer scorer(&library, 30, 70);
  const HttpRequest request = BrowserRequest(kChromeUa);
  ScoringInput input;
  input.request = &request;
  input.ja4 = kCurlJa4;
  const Verdict verdict = scorer.Score(input);
  EXPECT_EQ(verdict.score, 100);  // 140, capped.
  EXPECT_TRUE(Has(verdict, "known_automation:a"));
  EXPECT_TRUE(Has(verdict, "known_automation:b"));
}

// --- Policy -----------------------------------------------------------------

TEST(PolicyTest, ShadowAndEnforceWithHostOverrides) {
  PolicySettings settings;
  settings.enforce = false;
  settings.host_modes = {{"shop.test", HostMode::kEnforce},
                         {"*.api.test", HostMode::kEnforce},
                         {"open.api.test", HostMode::kShadow},
                         {"raw.test", HostMode::kOff}};
  const Policy policy(settings);

  Verdict bot;
  bot.score = 90;
  bot.bot_class = BotClass::kBot;
  PolicyDecision decision = policy.Decide(bot, "blog.test");
  EXPECT_FALSE(decision.enforce);
  EXPECT_EQ(decision.action, Action::kAllow);
  EXPECT_EQ(decision.would_action, Action::kBlock);

  decision = policy.Decide(bot, "shop.test");
  EXPECT_TRUE(decision.enforce);
  EXPECT_EQ(decision.action, Action::kBlock);

  EXPECT_TRUE(policy.EnforcedFor("v1.api.test"));
  EXPECT_FALSE(policy.EnforcedFor("open.api.test"));  // Exact wins.
  EXPECT_EQ(policy.ModeFor("raw.test"), HostMode::kOff);
  // Labels apply where the configuration says nothing about the host.
  EXPECT_EQ(policy.ModeFor("blog.test", HostMode::kEnforce),
            HostMode::kEnforce);
  EXPECT_EQ(policy.ModeFor("open.api.test", HostMode::kEnforce),
            HostMode::kShadow);

  Verdict suspicious;
  suspicious.bot_class = BotClass::kSuspicious;
  EXPECT_EQ(policy.Decide(suspicious, "shop.test").action, Action::kAllow);
}

}  // namespace
}  // namespace bot_shield
