#include "server/whoami.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "fp/library.h"

namespace bot_shield {
namespace {

WhoamiReport CurlReport() {
  WhoamiReport report;
  report.request_id = "local-1-1";
  report.host = "shop.test";
  report.mode = "shadow";
  report.ip = "203.0.113.7";
  report.ip_prefix = "203.0.113.0/24";
  report.user_agent = "curl/8.7.1";
  report.claimed_tool = "curl";
  report.http_version = "2";
  report.offered_h2 = true;
  report.ja4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
  report.score = 80;
  report.bot_class = "bot";
  report.reasons = {{"automation_user_agent", 60}, {"hosting_network", 20}};
  report.action = "allow";
  report.would_action = "block";
  return report;
}

TEST(WhoamiTest, HeadlineNamesWhatTheClientLooksLike) {
  EXPECT_EQ(WhoamiHeadline(CurlReport()), "curl, an HTTP tool or library");

  WhoamiReport browser;
  browser.user_agent = "Mozilla/5.0 ... Chrome/141.0.0.0 Safari/537.36";
  browser.claimed_family = "chrome";
  browser.claimed_major = 141;
  browser.claimed_os = "macos";
  browser.bot_class = "human";
  EXPECT_EQ(WhoamiHeadline(browser), "a real browser (Chrome 141 on macos)");
  browser.bot_class = "suspicious";
  EXPECT_EQ(WhoamiHeadline(browser),
            "something that claims to be Chrome 141 on macos but does not "
            "look like it");

  WhoamiReport crawler;
  crawler.reasons = {{"verified_crawler:googlebot", 0}};
  EXPECT_EQ(WhoamiHeadline(crawler), "a verified crawler (googlebot)");

  WhoamiReport automation = CurlReport();
  automation.reasons.emplace_back("known_automation:python_requests", 50);
  EXPECT_EQ(WhoamiHeadline(automation), "automation (python_requests)");

  EXPECT_EQ(WhoamiHeadline(WhoamiReport{}),
            "an anonymous client (no User-Agent)");
}

TEST(WhoamiTest, TextSaysWhatWouldHappen) {
  const std::string text = RenderWhoamiText(CurlReport());
  EXPECT_NE(text.find("You look like curl, an HTTP tool or library."),
            std::string::npos);
  EXPECT_NE(text.find("Verdict: bot, score 80."), std::string::npos);
  EXPECT_NE(text.find("On shop.test (shadow) you would be let through now; "
                      "in enforce mode, blocked."),
            std::string::npos);
  EXPECT_NE(text.find("+60  automation_user_agent"), std::string::npos);
  EXPECT_NE(text.find("no known browser"), std::string::npos);
  EXPECT_NE(text.find("TCP ? · TLS handshake ?"), std::string::npos);

  WhoamiReport relayed = CurlReport();
  relayed.tcp_rtt_us = 4'200;
  relayed.handshake_us = 151'000;
  EXPECT_NE(RenderWhoamiText(relayed).find(
                "TCP 4.2 ms · TLS handshake 151.0 ms (relayed"),
            std::string::npos);

  WhoamiReport enforced = CurlReport();
  enforced.mode = "enforce";
  enforced.action = "challenge";
  enforced.would_action = "challenge";
  EXPECT_NE(RenderWhoamiText(enforced).find(
                "On shop.test (enforce) you would be sent a JavaScript "
                "challenge."),
            std::string::npos);

  WhoamiReport off = CurlReport();
  off.mode = "off";
  EXPECT_NE(RenderWhoamiText(off).find("shop.test is off"), std::string::npos);
}

TEST(WhoamiTest, JsonAndHtml) {
  const nlohmann::json json =
      nlohmann::json::parse(RenderWhoamiJson(CurlReport()));
  EXPECT_EQ(json["verdict"]["would_action"], "block");
  EXPECT_EQ(json["verdict"]["reasons"][0]["weight"], 60);
  EXPECT_EQ(json["claims"]["tool"], "curl");
  EXPECT_EQ(json["network"]["ip_prefix"], "203.0.113.0/24");

  WhoamiReport hostile = CurlReport();
  hostile.user_agent = "<script>alert(1)</script>";
  const std::string html = RenderWhoamiHtml(hostile);
  EXPECT_EQ(html.find("<script>"), std::string::npos);
  EXPECT_NE(html.find("&lt;script&gt;"), std::string::npos);
  EXPECT_NE(html.find("<h1>You look like"), std::string::npos);
}

TEST(WhoamiTest, FormatFollowsQueryThenAccept) {
  EXPECT_EQ(ChooseWhoamiFormat("", "*/*"), WhoamiFormat::kText);
  EXPECT_EQ(ChooseWhoamiFormat("", "text/html,application/xhtml+xml"),
            WhoamiFormat::kHtml);
  EXPECT_EQ(ChooseWhoamiFormat("", "application/json"), WhoamiFormat::kJson);
  EXPECT_EQ(ChooseWhoamiFormat("x=1&format=json", "text/html"),
            WhoamiFormat::kJson);
  EXPECT_EQ(ChooseWhoamiFormat("format=text", "text/html"),
            WhoamiFormat::kText);
}

TEST(WhoamiTest, TlsEnginesFromTheLibrary) {
  const FingerprintLibrary& library = FingerprintLibrary::BuiltIn();
  const BrowserProfile* chromium = library.ProfileForEngine("chromium");
  ASSERT_NE(chromium, nullptr);
  ASSERT_FALSE(chromium->ja4_ciphers.empty());
  const std::string ja4 =
      "t13d1516h2_" + chromium->ja4_ciphers.front() + "_000000000000";
  const std::vector<std::string> engines = MatchingTlsEngines(library, ja4);
  EXPECT_NE(std::ranges::find(engines, "chromium"), engines.end());
  EXPECT_TRUE(
      MatchingTlsEngines(library, "t13d4907h2_000000000000_00").empty());
  EXPECT_TRUE(MatchingTlsEngines(library, "").empty());
}

}  // namespace
}  // namespace bot_shield
