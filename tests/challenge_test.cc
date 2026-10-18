#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>

#include "challenge/challenger.h"
#include "challenge/token.h"
#include "common/url.h"
#include "fp/http_request.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

constexpr int64_t kNow = 1'800'000'000;

// 32 bytes each, base64.
constexpr std::string_view kKeyA =
    "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
constexpr std::string_view kKeyB =
    "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=";

TokenKeys LoadKeys(std::string_view json) {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "bot_shield_keys_test.json";
  std::ofstream(path) << json;
  TokenKeys keys;
  std::string error;
  EXPECT_TRUE(TokenKeys::Load(path.string(), &keys, &error)) << error;
  std::filesystem::remove(path);
  return keys;
}

std::string KeysJson(std::string_view active, bool with_b) {
  std::string json =
      std::format(R"({{"active":"{}","keys":{{"a":"{}")", active, kKeyA);
  if (with_b) json += std::format(R"(,"b":"{}")", kKeyB);
  return json + "}}";
}

std::string Solve(std::string_view nonce, int difficulty) {
  for (int counter = 0;; ++counter) {
    const std::string text = std::to_string(counter);
    if (PowZeroBits(nonce, text) >= difficulty) return text;
  }
}

// The nonce embedded in a challenge page.
std::string NonceFromPage(const std::string& page) {
  const std::size_t start = page.find("var N=\"") + 7;
  return page.substr(start, page.find('"', start) - start);
}

TEST(TokenTest, RoundTripsAndRejectsTampering) {
  const TokenKeys keys = TokenKeys::Random();
  TokenClaims claims;
  claims.issued = kNow;
  claims.expires = kNow + 3600;
  claims.binding = ClientBinding::For("t13d1516h2_8daaf6152771_02713d6af862",
                                      "203.0.113.0/24");
  const std::string token = IssueToken(keys, claims);

  TokenClaims out;
  ASSERT_TRUE(VerifyToken(keys, token, kNow, &out));
  EXPECT_EQ(out.binding, claims.binding);
  EXPECT_EQ(out.expires, kNow + 3600);
  EXPECT_FALSE(VerifyToken(keys, token, kNow + 3600, &out));  // Expired.

  std::string forged = token;
  forged[3] = forged[3] == '9' ? '8' : '9';  // Issued time.
  EXPECT_FALSE(VerifyToken(keys, forged, kNow, &out));
  forged = token;
  forged.back() = forged.back() == 'a' ? 'b' : 'a';
  EXPECT_FALSE(VerifyToken(keys, forged, kNow, &out));
  EXPECT_FALSE(VerifyToken(TokenKeys::Random(), token, kNow, &out));
  EXPECT_FALSE(VerifyToken(keys, "", kNow, &out));
  EXPECT_FALSE(VerifyToken(keys, "v1.....", kNow, &out));
}

TEST(TokenTest, KeyRotationKeepsOldTokensValid) {
  const TokenKeys old_keys = LoadKeys(KeysJson("a", false));
  const TokenKeys rotated = LoadKeys(KeysJson("b", true));
  const TokenKeys dropped =
      LoadKeys(std::format(R"({{"active":"b","keys":{{"b":"{}"}}}})", kKeyB));
  TokenClaims claims;
  claims.expires = kNow + 60;
  claims.binding = ClientBinding::For("", "198.51.100.0/24");
  const std::string token = IssueToken(old_keys, claims);
  TokenClaims out;
  EXPECT_TRUE(VerifyToken(rotated, token, kNow, &out));
  EXPECT_FALSE(VerifyToken(dropped, token, kNow, &out));
  EXPECT_NE(IssueToken(rotated, claims).find(".b."), std::string::npos);
}

TEST(TokenTest, RejectsBadKeyFiles) {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "bot_shield_bad_keys.json";
  TokenKeys keys;
  std::string error;
  for (const std::string& json :
       {std::string("not json"), std::string(R"({"active":"a","keys":{}})"),
        std::string(R"({"active":"a","keys":{"a":"c2hvcnQ="}})"),
        std::string(R"({"active":"a","keys":{"a":"!!!"}})"),
        std::format(R"({{"active":"x","keys":{{"a":"{}"}}}})", kKeyA)}) {
    std::ofstream(path) << json;
    EXPECT_FALSE(TokenKeys::Load(path.string(), &keys, &error)) << json;
  }
  std::filesystem::remove(path);
  EXPECT_FALSE(TokenKeys::Load("/nonexistent/keys.json", &keys, &error));
}

TEST(TokenTest, NonceCarriesReturnPathAndExpires) {
  const TokenKeys keys = TokenKeys::Random();
  NonceClaims claims;
  claims.issued = kNow;
  claims.difficulty = 5;
  claims.binding = ClientBinding::For("ja4", "10.0.0.0/24");
  claims.return_path = "/shop?q=a.b&x=ü";
  const std::string nonce = IssueNonce(keys, claims);
  EXPECT_EQ(nonce.find_first_not_of("abcdefghijklmnopqrstuvwxyz"
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"),
            std::string::npos);
  NonceClaims out;
  ASSERT_TRUE(VerifyNonce(keys, nonce, kNow + 10, 300, &out));
  EXPECT_EQ(out.return_path, claims.return_path);
  EXPECT_EQ(out.difficulty, 5);
  EXPECT_FALSE(VerifyNonce(keys, nonce, kNow + 301, 300, &out));
  EXPECT_FALSE(VerifyNonce(keys, nonce, kNow - 120, 300, &out));  // Future.
  // A token is not a nonce.
  TokenClaims token;
  token.expires = kNow + 60;
  EXPECT_FALSE(VerifyNonce(keys, IssueToken(keys, token), kNow, 300, &out));
}

TEST(TokenTest, Helpers) {
  EXPECT_EQ(Base64UrlEncode(""), "");
  EXPECT_EQ(Base64UrlEncode("f"), "Zg");
  EXPECT_EQ(Base64UrlEncode("fo"), "Zm8");
  EXPECT_EQ(Base64UrlEncode("foo"), "Zm9v");
  EXPECT_EQ(Base64UrlEncode("\xfb\xff"), "-_8");
  std::string decoded;
  ASSERT_TRUE(Base64UrlDecode("-_8", &decoded));
  EXPECT_EQ(decoded, "\xfb\xff");
  EXPECT_FALSE(Base64UrlDecode("Z", &decoded));
  EXPECT_FALSE(Base64UrlDecode("Zm9v=", &decoded));

  EXPECT_TRUE(IsSafeReturnPath("/"));
  EXPECT_TRUE(IsSafeReturnPath("/a/b?c=//d"));
  EXPECT_FALSE(IsSafeReturnPath(""));
  EXPECT_FALSE(IsSafeReturnPath("//evil.test/"));
  EXPECT_FALSE(IsSafeReturnPath("/\\evil.test/"));
  EXPECT_FALSE(IsSafeReturnPath("https://evil.test/"));
  EXPECT_FALSE(IsSafeReturnPath("/a\r\nSet-Cookie: x=1"));

  // SHA-256("abc:0") starts with 0x5f: one leading zero bit.
  EXPECT_EQ(PowZeroBits("abc", "0"), 1);
  EXPECT_GE(PowZeroBits("x", Solve("x", 8)), 8);
}

ChallengeSettings Settings() {
  ChallengeSettings settings;
  settings.keys = TokenKeys::Random();
  settings.suspicious_difficulty = 6;
  settings.bot_difficulty = 8;
  settings.token_ttl = std::chrono::seconds(600);
  return settings;
}

std::string Signals(std::string_view json) { return Base64UrlEncode(json); }

constexpr std::string_view kGoodSignals =
    R"({"wd":false,"lang":2,"hc":8,"plat":"MacIntel","brands":["Chromium"],)"
    R"("tz":"Europe/Moscow","sw":1512,"ph":false,"ms":40})";

TEST(ChallengerTest, PassesSolvedChallengeAndIssuesToken) {
  const Challenger challenger(Settings());
  EXPECT_EQ(challenger.DifficultyFor(BotClass::kSuspicious), 6);
  EXPECT_EQ(challenger.DifficultyFor(BotClass::kBot), 8);
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const std::string page = challenger.Page(binding, 6, "/cart?id=1", kNow);
  EXPECT_NE(page.find("<script>"), std::string::npos);
  EXPECT_NE(page.find("D=6;"), std::string::npos);
  const std::string nonce = NonceFromPage(page);

  const std::string query = "n=" + PercentEncode(nonce) +
                            "&c=" + Solve(nonce, 6) +
                            "&s=" + Signals(kGoodSignals);
  const Challenger::Result result = challenger.Verify(query, binding, kNow + 2);
  ASSERT_TRUE(result.passed) << result.reason;
  EXPECT_EQ(result.return_path, "/cart?id=1");
  EXPECT_TRUE(result.set_cookie.starts_with("__bs=v1."));
  EXPECT_NE(result.set_cookie.find("Max-Age=600; HttpOnly; Secure"),
            std::string::npos);

  HttpRequest request;
  request.headers = {
      {"cookie", "a=1; " +
                     result.set_cookie.substr(0, result.set_cookie.find(';')) +
                     "; b=2"}};
  EXPECT_TRUE(challenger.HasValidToken(request, binding, kNow + 10));
  EXPECT_FALSE(challenger.HasValidToken(request, binding, kNow + 700));
  EXPECT_FALSE(challenger.HasValidToken(
      request, ClientBinding::For("other", "192.0.2.0/24"), kNow + 10));
  EXPECT_FALSE(challenger.HasValidToken(
      request, ClientBinding::For("ja4", "192.0.3.0/24"), kNow + 10));
  EXPECT_FALSE(challenger.HasValidToken(HttpRequest(), binding, kNow));
}

TEST(ChallengerTest, RejectsBadSolutions) {
  const Challenger challenger(Settings());
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const std::string nonce =
      NonceFromPage(challenger.Page(binding, 8, "//evil.test", kNow));
  const std::string counter = Solve(nonce, 8);
  const auto verify = [&](std::string_view n, std::string_view c,
                          std::string_view signals, const ClientBinding& who,
                          int64_t now) {
    return challenger.Verify("n=" + PercentEncode(n) + "&c=" + std::string(c) +
                                 "&s=" + Signals(signals),
                             who, now);
  };
  const Challenger::Result ok =
      verify(nonce, counter, kGoodSignals, binding, kNow);
  ASSERT_TRUE(ok.passed);
  EXPECT_EQ(ok.return_path, "/");  // Unsafe return path replaced.

  EXPECT_EQ(verify("junk", counter, kGoodSignals, binding, kNow).reason,
            "bad_nonce");
  EXPECT_EQ(verify(nonce, counter, kGoodSignals, binding, kNow + 301).reason,
            "bad_nonce");
  EXPECT_EQ(verify(nonce, counter, kGoodSignals,
                   ClientBinding::For("curl", "192.0.2.0/24"), kNow)
                .reason,
            "binding");
  std::string wrong = "0";
  while (PowZeroBits(nonce, wrong) >= 8) wrong += '1';
  EXPECT_EQ(verify(nonce, wrong, kGoodSignals, binding, kNow).reason, "pow");
  EXPECT_EQ(verify(nonce, "-1", kGoodSignals, binding, kNow).reason, "pow");
  EXPECT_EQ(verify(nonce, counter, "[1]", binding, kNow).reason, "signals");
  EXPECT_EQ(
      verify(nonce, counter, R"({"wd":true,"lang":2})", binding, kNow).reason,
      "webdriver");
  EXPECT_EQ(
      verify(nonce, counter, R"({"ph":true,"lang":2})", binding, kNow).reason,
      "automation_globals");
  EXPECT_EQ(verify(nonce, counter, R"({"lang":2,"brands":["HeadlessChrome"]})",
                   binding, kNow)
                .reason,
            "headless");
  EXPECT_EQ(verify(nonce, counter, R"({"lang":0})", binding, kNow).reason,
            "no_languages");
  EXPECT_FALSE(challenger.Verify("", binding, kNow).passed);
}

TEST(ChallengerTest, StripsOwnCookie) {
  EXPECT_EQ(Challenger::StripCookie("__bs=v1.x"), "");
  EXPECT_EQ(Challenger::StripCookie("a=1; __bs=v1.x; b=2"), "a=1; b=2");
  EXPECT_EQ(Challenger::StripCookie("a=1;__bs=x"), "a=1");
  EXPECT_EQ(Challenger::StripCookie("__bsx=1; a=2"), "__bsx=1; a=2");
  EXPECT_EQ(Challenger::StripCookie(""), "");
}

TEST(ChallengerTest, DetectsNavigation) {
  HttpRequest request;
  request.method = "GET";
  EXPECT_FALSE(IsNavigation(request));
  request.headers = {{"accept", "text/html,application/xhtml+xml"}};
  EXPECT_TRUE(IsNavigation(request));
  request.headers.emplace_back("sec-fetch-mode", "cors");
  EXPECT_FALSE(IsNavigation(request));
  request.headers = {{"sec-fetch-mode", "navigate"}};
  EXPECT_TRUE(IsNavigation(request));
  request.method = "POST";
  EXPECT_FALSE(IsNavigation(request));
}

}  // namespace
}  // namespace bot_shield
