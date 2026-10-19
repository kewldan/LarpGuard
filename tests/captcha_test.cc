#include "challenge/captcha.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "challenge/challenger.h"
#include "challenge/puzzle.h"
#include "challenge/token.h"
#include "common/hash.h"
#include "common/url.h"
#include "fp/http_request.h"
#include "test_util.h"

namespace bot_shield {
namespace {

constexpr int64_t kNow = 1'800'000'000;
constexpr std::string_view kUserAgent =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

nlohmann::json GoodSignals() {
  return {{"wd", false},
          {"lang", 2},
          {"ph", false},
          {"brands", {"Chromium", "Google Chrome"}},
          {"ua", Sha256Hex(kUserAgent, 16)},
          {"cv", "0123456789abcdef"},
          {"cvn", 0},
          {"glr", "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified)"},
          {"glp", "aaaa"},
          {"au", "bbbb"},
          {"fm", "110101"},
          {"fn", 14},
          {"sc", {1512, 982, 1512, 950, 30, 200, 1512, 950, 1512, 860}},
          {"pl", 5},
          {"nt", 0},
          {"cdp", 0},
          {"wm", 0}};
}

std::string Encode(const nlohmann::json& json) {
  return Base64UrlEncode(json.dump());
}

std::string Solve(std::string_view nonce, int bits) {
  for (int counter = 0;; ++counter) {
    const std::string text = std::to_string(counter);
    if (PowZeroBits(nonce, text) >= bits) return text;
  }
}

// N="..." of a gateway page.
std::string NonceFromPage(std::string_view page) {
  const std::size_t start = page.find("N=\"") + 3;
  return std::string(page.substr(start, page.find('"', start) - start));
}

ChallengeSettings ChallengeConfig() {
  ChallengeSettings settings;
  settings.keys = TokenKeys::Random();
  settings.token_ttl = std::chrono::seconds(600);
  return settings;
}

TEST(SignalCheckTest, SortsFindingsIntoTiers) {
  SignalCheck check = CheckSignals(GoodSignals(), kUserAgent);
  EXPECT_TRUE(check.fatal.empty());
  EXPECT_TRUE(check.suspicious.empty());
  EXPECT_TRUE(check.soft.empty());
  EXPECT_EQ(check.client_fp.size(), 16U);

  const auto with = [](std::string_view key, nlohmann::json value) {
    nlohmann::json signals = GoodSignals();
    signals[std::string(key)] = std::move(value);
    return CheckSignals(signals, kUserAgent);
  };
  EXPECT_EQ(with("wd", true).fatal, "webdriver");
  EXPECT_EQ(with("brands", {"HeadlessChrome"}).fatal, "headless");
  EXPECT_EQ(with("cdp", 1).suspicious, "cdp");
  EXPECT_EQ(with("wm", 3).suspicious, "worker_mismatch");
  EXPECT_EQ(with("ua", "0000000000000000").suspicious, "ua_mismatch");
  EXPECT_EQ(with("nt", 2).suspicious, "tampered_natives");
  EXPECT_EQ(with("lang", 0).suspicious, "no_languages");
  EXPECT_EQ(with("glr", "Google SwiftShader").soft,
            std::vector<std::string>{"software_renderer"});
  EXPECT_EQ(with("sc", {800, 600, 800, 600, 24, 100, 0, 0, 800, 600}).soft,
            std::vector<std::string>{"headless_screen"});
  EXPECT_EQ(with("cvn", 1).soft, std::vector<std::string>{"canvas_noise"});
  EXPECT_EQ(with("cv", "").soft, std::vector<std::string>{"canvas_blocked"});
  EXPECT_EQ(with("fn", 0).soft, std::vector<std::string>{"no_fonts"});
  EXPECT_EQ(with("pl", 0).soft, std::vector<std::string>{"no_plugins"});
  // Plugins and fonts only count for desktop browsers.
  nlohmann::json mobile = GoodSignals();
  mobile["pl"] = 0;
  mobile["fn"] = 0;
  mobile["ua"] = Sha256Hex("Mozilla/5.0 (Linux; Android 14)", 16);
  EXPECT_TRUE(
      CheckSignals(mobile, "Mozilla/5.0 (Linux; Android 14)").soft.empty());
  EXPECT_EQ(CheckSignals(nlohmann::json::array(), kUserAgent).fatal, "signals");
}

TEST(SignalCheckTest, ChallengerEscalatesInsteadOfDeciding) {
  const Challenger challenger(ChallengeConfig());
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const auto verify = [&](const nlohmann::json& signals) {
    const std::string nonce =
        NonceFromPage(challenger.Page(binding, 4, "/x", kNow));
    return challenger.Verify("n=" + PercentEncode(nonce) + "&c=" +
                                 Solve(nonce, 4) + "&s=" + Encode(signals),
                             binding, kUserAgent, kNow);
  };
  Challenger::Result result = verify(GoodSignals());
  EXPECT_TRUE(result.passed);
  EXPECT_FALSE(result.escalate);

  nlohmann::json soft = GoodSignals();
  soft["glr"] = "llvmpipe (LLVM 15.0.7, 256 bits)";
  result = verify(soft);
  EXPECT_TRUE(result.passed);
  EXPECT_TRUE(result.escalate);
  EXPECT_EQ(result.soft, std::vector<std::string>{"software_renderer"});

  nlohmann::json cdp = GoodSignals();
  cdp["cdp"] = 1;
  result = verify(cdp);
  EXPECT_FALSE(result.passed);
  EXPECT_TRUE(result.escalate);
  EXPECT_EQ(result.reason, "cdp");

  nlohmann::json webdriver = GoodSignals();
  webdriver["wd"] = true;
  result = verify(webdriver);
  EXPECT_FALSE(result.passed);
  EXPECT_FALSE(result.escalate);
}

TEST(SignalCheckTest, TokensCarryTheirLevel) {
  const Challenger challenger(ChallengeConfig());
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const auto clearance = [&](int level) {
    const std::string cookie = challenger.ClearanceCookie(binding, level, kNow);
    HttpRequest request;
    request.headers = {{"cookie", cookie.substr(0, cookie.find(';'))}};
    return challenger.FindClearance(request, binding, kNow + 1);
  };
  const std::optional<Clearance> js = clearance(kTokenLevelJs);
  const std::optional<Clearance> solved = clearance(kTokenLevelCaptcha);
  ASSERT_TRUE(js.has_value() && solved.has_value());
  EXPECT_EQ(js->level, kTokenLevelJs);
  EXPECT_EQ(solved->level, kTokenLevelCaptcha);
  EXPECT_TRUE(challenger.ClearanceCookie(binding, kTokenLevelCaptcha, kNow)
                  .starts_with("__bs=v2."));
}

TEST(PuzzleTest, RendersDeterministicPngs) {
  const Puzzle a = GeneratePuzzle(42);
  const Puzzle b = GeneratePuzzle(42);
  const Puzzle c = GeneratePuzzle(43);
  EXPECT_TRUE(a.image_png.starts_with("\x89PNG\r\n\x1a\n"));
  EXPECT_TRUE(a.sample_png.starts_with("\x89PNG\r\n\x1a\n"));
  EXPECT_EQ(a.image_png, b.image_png);
  EXPECT_NE(a.image_png, c.image_png);
  EXPECT_GT(a.x, 0);
  EXPECT_LT(a.x, 300);
  EXPECT_GT(a.y, 0);
  EXPECT_LT(a.y, 200);
  EXPECT_GE(a.radius, 20);
  EXPECT_TRUE(PngDataUri("x").starts_with("data:image/png;base64,"));

  Raster raster(4, 4, {255, 255, 255});
  raster.FillPolygon({{0, 0}, {4, 0}, {4, 2}, {0, 2}}, {0, 0, 0}, 1.0);
  EXPECT_EQ(raster.At(1, 1).r, 0);
  EXPECT_EQ(raster.At(1, 3).r, 255);
  EXPECT_EQ(raster.Half().At(0, 0).r, 0);
}

// A hand-like approach to (x, y): a curve with uneven timing.
std::string Telemetry(int x, int y, bool trusted = true,
                      bool straight = false) {
  nlohmann::json points = nlohmann::json::array();
  for (int i = 0; i <= 10; ++i) {
    const double t = i / 10.0;
    const double bend = straight ? 0 : 25 * t * (1 - t);
    points.push_back({static_cast<int>(x - 80 * (1 - t) + bend),
                      static_cast<int>(y - 50 * (1 - t) - bend),
                      400 + i * 16 + (straight ? 0 : (i * i) % 7)});
  }
  return Encode(
      {{"tr", trusted ? 1 : 0}, {"pt", "mouse"}, {"ms", 900}, {"p", points}});
}

TEST(CaptchaTest, BuiltinPuzzleRounds) {
  const Challenger challenger(ChallengeConfig());
  CaptchaSettings settings;
  settings.provider = CaptchaProvider::kBuiltin;
  settings.rounds = 2;
  settings.difficulty = 4;
  settings.min_answer = std::chrono::milliseconds(800);
  settings.test_seed = 100;
  Captcha captcha(settings, &challenger);
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const int64_t shown = kNow * 1000;
  const std::string page = captcha.Page(binding, "/checkout", shown);
  EXPECT_NE(page.find("id=\"bs-p\""), std::string::npos);
  EXPECT_NE(page.find("data:image/png;base64,"), std::string::npos);
  // The answer never appears in the page.
  const Puzzle first = GeneratePuzzle(100);
  std::string nonce = NonceFromPage(page);
  EXPECT_TRUE(nonce.starts_with("p1."));

  const auto answer = [&](const std::string& n, int x, int y, int64_t at,
                          const std::string& telemetry) {
    return captcha.AnswerPuzzle(
        std::format("n={}&c={}&x={}&y={}&m={}&s={}", PercentEncode(n),
                    Solve(n, 4), x, y, telemetry, Encode(GoodSignals())),
        binding, kUserAgent, at);
  };
  // Instant answers are scripts.
  Captcha::Answer result =
      answer(nonce, first.x, first.y, shown + 100, Telemetry(first.x, first.y));
  EXPECT_EQ(result.outcome, "retry:too_fast");
  // That nonce is spent; the retry brought a new puzzle (seed 101).
  EXPECT_EQ(
      answer(nonce, first.x, first.y, shown + 2000, Telemetry(first.x, first.y))
          .outcome,
      "failed:replay");
  nonce = nlohmann::json::parse(result.body)["next"]["n"];
  const Puzzle retry = GeneratePuzzle(101);
  // A wrong click: another new puzzle (seed 102).
  result = answer(nonce, retry.x + 60, retry.y, shown + 2000,
                  Telemetry(retry.x + 60, retry.y));
  EXPECT_EQ(result.outcome, "retry:wrong");
  nonce = nlohmann::json::parse(result.body)["next"]["n"];
  const Puzzle round1 = GeneratePuzzle(102);
  result = answer(nonce, round1.x + 2, round1.y - 2, shown + 4000,
                  Telemetry(round1.x + 2, round1.y - 2));
  ASSERT_EQ(result.outcome, "next") << result.body;
  EXPECT_TRUE(result.set_cookie.empty());
  nonce = nlohmann::json::parse(result.body)["next"]["n"];
  const Puzzle round2 = GeneratePuzzle(103);
  result = answer(nonce, round2.x, round2.y, shown + 6000,
                  Telemetry(round2.x, round2.y));
  ASSERT_EQ(result.outcome, "passed") << result.body;
  EXPECT_TRUE(result.set_cookie.starts_with("__bs=v2."));
  EXPECT_EQ(nlohmann::json::parse(result.body)["done"], "/checkout");
  EXPECT_EQ(result.client_fp.size(), 16U);
}

TEST(CaptchaTest, BuiltinPuzzleRefusesScripts) {
  const Challenger challenger(ChallengeConfig());
  CaptchaSettings settings;
  settings.provider = CaptchaProvider::kBuiltin;
  settings.difficulty = 4;
  settings.test_seed = 500;
  Captcha captcha(settings, &challenger);
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const int64_t shown = kNow * 1000;
  const Puzzle puzzle = GeneratePuzzle(500);
  const auto fresh = [&] {
    return NonceFromPage(captcha.Page(binding, "/", shown));
  };
  const auto answer = [&](const std::string& n, const std::string& telemetry,
                          const ClientBinding& who,
                          const nlohmann::json& signals) {
    return captcha
        .AnswerPuzzle(std::format("n={}&c={}&x={}&y={}&m={}&s={}",
                                  PercentEncode(n), Solve(n, 4), puzzle.x,
                                  puzzle.y, telemetry, Encode(signals)),
                      who, kUserAgent, shown + 2000)
        .outcome;
  };
  EXPECT_EQ(answer(fresh(), Telemetry(puzzle.x, puzzle.y, false), binding,
                   GoodSignals()),
            "failed:untrusted_click");
  EXPECT_EQ(answer(fresh(), Telemetry(puzzle.x, puzzle.y, true, true), binding,
                   GoodSignals()),
            "failed:pointer");
  EXPECT_EQ(answer(fresh(), Encode({{"tr", 1}, {"pt", "mouse"}, {"p", {}}}),
                   binding, GoodSignals()),
            "failed:pointer");
  EXPECT_EQ(answer(fresh(), Telemetry(puzzle.x, puzzle.y),
                   ClientBinding::For("other", "192.0.2.0/24"), GoodSignals()),
            "failed:binding");
  nlohmann::json webdriver = GoodSignals();
  webdriver["wd"] = true;
  EXPECT_EQ(answer(fresh(), Telemetry(puzzle.x, puzzle.y), binding, webdriver),
            "failed:webdriver");
  EXPECT_EQ(
      captcha.AnswerPuzzle("n=p1.x.y", binding, kUserAgent, shown).outcome,
      "failed:bad_nonce");
  // Touch has no movement before the tap. (The five pages above used seeds
  // 500..504; this one gets 505.)
  const Puzzle touch_puzzle = GeneratePuzzle(505);
  const std::string touch_nonce = fresh();
  const Captcha::Answer touch = captcha.AnswerPuzzle(
      std::format("n={}&c={}&x={}&y={}&m={}&s={}", PercentEncode(touch_nonce),
                  Solve(touch_nonce, 4), touch_puzzle.x, touch_puzzle.y,
                  Encode({{"tr", 1}, {"pt", "touch"}, {"p", {}}}),
                  Encode(GoodSignals())),
      binding, kUserAgent, shown + 2000);
  EXPECT_EQ(touch.outcome, "next");
}

TEST(CaptchaTest, ParsesSiteverify) {
  SiteverifyResult result = ParseSiteverify(
      R"({"success":true,"hostname":"shop.test",)"
      R"("challenge_ts":"2027-01-15T08:00:00.123Z","cdata":"abc"})");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(result.hostname, "shop.test");
  EXPECT_EQ(result.cdata, "abc");
  EXPECT_EQ(result.challenge_ts, 1800000000);
  result = ParseSiteverify(
      R"({"success":false,"error-codes":["invalid-input-response"]})");
  EXPECT_FALSE(result.success);
  EXPECT_EQ(result.error, "invalid-input-response");
  EXPECT_FALSE(ParseSiteverify("nope").success);
}

TEST(CaptchaTest, TurnstileGoesThroughSiteverify) {
  std::mutex mutex;
  std::string last_request;
  std::string answer_json;
  testing::TestServer provider([&](const std::string& head) {
    const std::scoped_lock lock(mutex);
    last_request = head;
    return std::format(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: {}\r\n\r\n{}",
        answer_json.size(), answer_json);
  });
  const Challenger challenger(ChallengeConfig());
  CaptchaSettings settings;
  settings.provider = CaptchaProvider::kTurnstile;
  settings.site_key = "0x4AAA\"<site>";
  settings.secret = "s3cret";
  settings.verify_url =
      std::format("http://127.0.0.1:{}/siteverify", provider.port());
  settings.difficulty = 4;
  Captcha captcha(settings, &challenger);
  const ClientBinding binding = ClientBinding::For("ja4", "192.0.2.0/24");
  const int64_t now_ms = kNow * 1000;

  int runs = 0;
  const auto run = [&](const std::string& reply, const ClientBinding& who,
                       std::string* nonce_out = nullptr) {
    // A second apart: pages of the same second share their nonce.
    const int64_t page_ms = now_ms + int64_t{1000} * runs;
    const std::string page = captcha.Page(binding, "/login", page_ms);
    EXPECT_NE(page.find("cf-turnstile"), std::string::npos);
    EXPECT_NE(page.find("0x4AAA&quot;&lt;site&gt;"), std::string::npos);
    const std::string nonce = NonceFromPage(page);
    if (nonce_out != nullptr) *nonce_out = nonce;
    {
      const std::scoped_lock lock(mutex);
      answer_json = reply;
      std::size_t at = 0;
      while ((at = answer_json.find("CDATA")) != std::string::npos) {
        answer_json.replace(at, 5, Sha256Hex(nonce, 32));
      }
    }
    Captcha::Verdict immediate;
    Captcha::Verdict later;
    std::atomic<bool> called{false};
    const bool queued = captcha.VerifyWidget(
        std::format("n={}&c={}&t=provider-token-{}&s={}", PercentEncode(nonce),
                    Solve(nonce, 4), ++runs, Encode(GoodSignals())),
        who, kUserAgent, "shop.test", "198.51.100.7", page_ms + 500, &immediate,
        [&](Captcha::Verdict verdict) {
          later = std::move(verdict);
          called = true;
        });
    if (!queued) return immediate;
    captcha.WaitIdle();
    EXPECT_TRUE(called);
    return later;
  };
  Captcha::Verdict verdict = run(
      R"({"success":true,"hostname":"shop.test","cdata":"CDATA"})", binding);
  EXPECT_TRUE(verdict.passed) << verdict.reason;
  EXPECT_TRUE(verdict.set_cookie.starts_with("__bs=v2."));
  EXPECT_EQ(verdict.return_path, "/login");
  {
    const std::scoped_lock lock(mutex);
    EXPECT_NE(last_request.find("secret=s3cret&response=provider-token-1&"
                                "remoteip=198.51.100.7"),
              std::string::npos)
        << last_request;
  }
  EXPECT_EQ(
      run(R"({"success":true,"hostname":"evil.test","cdata":"CDATA"})", binding)
          .reason,
      "failed:hostname");
  EXPECT_EQ(
      run(R"({"success":true,"hostname":"shop.test","cdata":"other"})", binding)
          .reason,
      "failed:cdata");
  EXPECT_EQ(run(R"({"success":false,"error-codes":["timeout-or-duplicate"]})",
                binding)
                .reason,
            "failed:provider:timeout-or-duplicate");
  EXPECT_EQ(
      run(R"({"success":true})", ClientBinding::For("other", "192.0.2.0/24"))
          .reason,
      "failed:binding");
}

}  // namespace
}  // namespace bot_shield
