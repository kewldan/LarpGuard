#include "challenge/captcha.h"

#include <openssl/aead.h>
#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "challenge/challenger.h"
#include "challenge/puzzle.h"
#include "challenge/scripts.h"
#include "challenge/token.h"
#include "common/hash.h"
#include "common/url.h"
#include "net/http_client.h"

namespace bot_shield {
namespace {

constexpr std::size_t kAeadNonce = 12;
constexpr int64_t kChallengeTsWindow = 300;  // Seconds.

std::vector<std::string_view> Split(std::string_view text, char separator) {
  std::vector<std::string_view> parts;
  while (true) {
    const std::size_t at = text.find(separator);
    parts.push_back(text.substr(0, at));
    if (at == std::string_view::npos) return parts;
    text.remove_prefix(at + 1);
  }
}

bool ParseInt(std::string_view text, int64_t* value) {
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), *value);
  return ec == std::errc() && ptr == text.data() + text.size() && !text.empty();
}

std::string HtmlEscape(std::string_view text) {
  std::string out;
  for (const char c : text) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&#39;";
        break;
      default:
        out.push_back(c);
    }
  }
  return out;
}

// AES-256-GCM key for puzzle nonces, derived from a token key.
std::array<uint8_t, 32> PuzzleKey(std::string_view secret) {
  static constexpr std::string_view kLabel = "larpguard puzzle v1";
  std::array<uint8_t, 32> key{};
  unsigned int size = 0;
  HMAC(EVP_sha256(), secret.data(), secret.size(),
       reinterpret_cast<const uint8_t*>(kLabel.data()), kLabel.size(),
       key.data(), &size);
  return key;
}

struct PuzzleClaims {
  int64_t issued_ms = 0;
  int round = 1;
  ClientBinding binding;
  int x = 0;
  int y = 0;
  int radius = 0;
  std::string return_path;
};

// p1.<key id>.<base64url(iv | ciphertext | tag)>
std::string SealPuzzle(const TokenKeys& keys, const PuzzleClaims& claims) {
  const std::string plain =
      std::format("{}|{}|{}|{}|{}|{}|{}|{}", claims.issued_ms, claims.round,
                  claims.binding.ja4_hash, claims.binding.ip_hash, claims.x,
                  claims.y, claims.radius, Base64UrlEncode(claims.return_path));
  const std::string& id = keys.active_id();
  const std::array<uint8_t, 32> key = PuzzleKey(keys.Secret(id));
  EVP_AEAD_CTX ctx;
  EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key.data(), key.size(),
                    EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr);
  std::string sealed(
      kAeadNonce + plain.size() + EVP_AEAD_max_overhead(EVP_aead_aes_256_gcm()),
      '\0');
  auto* out = reinterpret_cast<uint8_t*>(sealed.data());
  RAND_bytes(out, kAeadNonce);
  std::size_t size = 0;
  EVP_AEAD_CTX_seal(
      &ctx, out + kAeadNonce, &size, sealed.size() - kAeadNonce, out,
      kAeadNonce, reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
      reinterpret_cast<const uint8_t*>(id.data()), id.size());
  EVP_AEAD_CTX_cleanup(&ctx);
  sealed.resize(kAeadNonce + size);
  return std::format("p1.{}.{}", id, Base64UrlEncode(sealed));
}

bool OpenPuzzle(const TokenKeys& keys, std::string_view nonce,
                PuzzleClaims* claims) {
  const std::vector<std::string_view> parts = Split(nonce, '.');
  std::string sealed;
  if (parts.size() != 3 || parts[0] != "p1" ||
      !Base64UrlDecode(parts[2], &sealed) || sealed.size() <= kAeadNonce) {
    return false;
  }
  const std::string_view secret = keys.Secret(parts[1]);
  if (secret.empty()) return false;
  const std::array<uint8_t, 32> key = PuzzleKey(secret);
  EVP_AEAD_CTX ctx;
  EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key.data(), key.size(),
                    EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr);
  std::string plain(sealed.size(), '\0');
  std::size_t size = 0;
  const auto* in = reinterpret_cast<const uint8_t*>(sealed.data());
  const bool opened =
      EVP_AEAD_CTX_open(&ctx, reinterpret_cast<uint8_t*>(plain.data()), &size,
                        plain.size(), in, kAeadNonce, in + kAeadNonce,
                        sealed.size() - kAeadNonce,
                        reinterpret_cast<const uint8_t*>(parts[1].data()),
                        parts[1].size()) == 1;
  EVP_AEAD_CTX_cleanup(&ctx);
  if (!opened) return false;
  plain.resize(size);
  const std::vector<std::string_view> fields = Split(plain, '|');
  int64_t round = 0;
  int64_t x = 0;
  int64_t y = 0;
  int64_t radius = 0;
  PuzzleClaims out;
  if (fields.size() != 8 || !ParseInt(fields[0], &out.issued_ms) ||
      !ParseInt(fields[1], &round) || !ParseInt(fields[4], &x) ||
      !ParseInt(fields[5], &y) || !ParseInt(fields[6], &radius) ||
      !Base64UrlDecode(fields[7], &out.return_path)) {
    return false;
  }
  out.round = static_cast<int>(round);
  out.binding = {std::string(fields[2]), std::string(fields[3])};
  out.x = static_cast<int>(x);
  out.y = static_cast<int>(y);
  out.radius = static_cast<int>(radius);
  *claims = std::move(out);
  return true;
}

nlohmann::json DecodeJson(std::string_view encoded) {
  std::string text;
  return Base64UrlDecode(encoded, &text)
             ? nlohmann::json::parse(text, nullptr, false)
             : nlohmann::json();
}

bool PowOk(std::string_view nonce, std::string_view counter, int difficulty) {
  return !counter.empty() && counter.size() <= 12 &&
         counter.find_first_not_of("0123456789") == std::string_view::npos &&
         PowZeroBits(nonce, counter) >= difficulty;
}

// The pointer trace of a mouse click: a hand moves in curves at an uneven
// pace and ends on the click; a script that warps to the answer does not.
// Touch and pen clicks have no movement before them.
std::string_view CheckPointer(const nlohmann::json& telemetry, int click_x,
                              int click_y) {
  if (!telemetry.is_object()) return "telemetry";
  if (telemetry.value("tr", 0) != 1) return "untrusted_click";
  const std::string type = telemetry.value("pt", std::string("mouse"));
  if (type == "touch" || type == "pen") return {};
  const auto trace = telemetry.find("p");
  if (trace == telemetry.end() || !trace->is_array()) return "pointer";
  struct Sample {
    double x;
    double y;
    double t;
  };
  std::vector<Sample> points;
  for (const auto& item : *trace) {
    if (!item.is_array() || item.size() != 3 || !item[0].is_number() ||
        !item[1].is_number() || !item[2].is_number()) {
      return "pointer";
    }
    points.push_back(
        {item[0].get<double>(), item[1].get<double>(), item[2].get<double>()});
  }
  if (points.size() < 4) return "pointer";
  double length = 0;
  for (std::size_t i = 1; i < points.size(); ++i) {
    length += std::hypot(points[i].x - points[i - 1].x,
                         points[i].y - points[i - 1].y);
  }
  const Sample& last = points.back();
  if (length < 20 || std::hypot(last.x - click_x, last.y - click_y) > 30) {
    return "pointer";
  }
  // Not one straight line...
  const Sample& first = points.front();
  const double dx = last.x - first.x;
  const double dy = last.y - first.y;
  const double span = std::hypot(dx, dy);
  double deviation = 0;
  for (const Sample& p : points) {
    deviation = std::max(
        deviation,
        span < 1
            ? std::hypot(p.x - first.x, p.y - first.y)
            : std::fabs(dy * (p.x - first.x) - dx * (p.y - first.y)) / span);
  }
  // ...and not at a perfectly even pace.
  double min_gap = 1e9;
  double max_gap = 0;
  for (std::size_t i = 1; i < points.size(); ++i) {
    const double gap = points[i].t - points[i - 1].t;
    min_gap = std::min(min_gap, gap);
    max_gap = std::max(max_gap, gap);
  }
  if (deviation < 1.5 || max_gap - min_gap < 2) return "pointer";
  return {};
}

// "2026-10-18T22:10:28Z", "...28.123Z" or "...28+00:00", in UTC.
int64_t ParseTimestamp(std::string_view text) {
  if (text.size() < 19 || text[4] != '-' || text[7] != '-' || text[10] != 'T' ||
      text[13] != ':' || text[16] != ':') {
    return 0;
  }
  const auto field = [text](std::size_t at, std::size_t size) {
    int64_t value = -1;
    if (!ParseInt(text.substr(at, size), &value)) return int64_t{-1};
    return value;
  };
  const std::chrono::year_month_day day{
      std::chrono::year(static_cast<int>(field(0, 4))),
      std::chrono::month(static_cast<unsigned>(field(5, 2))),
      std::chrono::day(static_cast<unsigned>(field(8, 2)))};
  const int64_t hour = field(11, 2);
  const int64_t minute = field(14, 2);
  const int64_t second = field(17, 2);
  if (!day.ok() || hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
      second < 0 || second > 60) {
    return 0;
  }
  return std::chrono::sys_days(day).time_since_epoch() /
             std::chrono::seconds(1) +
         hour * 3600 + minute * 60 + second;
}

std::string Json(const nlohmann::json& value) { return value.dump(); }

}  // namespace

bool ParseCaptchaProvider(std::string_view text, CaptchaProvider* provider) {
  if (text.empty() || text == "off") {
    *provider = CaptchaProvider::kNone;
  } else if (text == "builtin") {
    *provider = CaptchaProvider::kBuiltin;
  } else if (text == "turnstile") {
    *provider = CaptchaProvider::kTurnstile;
  } else if (text == "hcaptcha") {
    *provider = CaptchaProvider::kHcaptcha;
  } else if (text == "recaptcha") {
    *provider = CaptchaProvider::kRecaptcha;
  } else {
    return false;
  }
  return true;
}

std::string_view CaptchaProviderName(CaptchaProvider provider) {
  switch (provider) {
    case CaptchaProvider::kNone:
      return "off";
    case CaptchaProvider::kBuiltin:
      return "builtin";
    case CaptchaProvider::kTurnstile:
      return "turnstile";
    case CaptchaProvider::kHcaptcha:
      return "hcaptcha";
    case CaptchaProvider::kRecaptcha:
      return "recaptcha";
  }
  return "off";
}

SiteverifyResult ParseSiteverify(std::string_view json) {
  SiteverifyResult result;
  const nlohmann::json root = nlohmann::json::parse(json, nullptr, false);
  if (!root.is_object()) {
    result.error = "bad_response";
    return result;
  }
  result.success = root.value("success", false);
  result.hostname = root.value("hostname", std::string());
  result.cdata = root.value("cdata", std::string());
  result.challenge_ts =
      ParseTimestamp(root.value("challenge_ts", std::string()));
  if (const auto codes = root.find("error-codes");
      codes != root.end() && codes->is_array() && !codes->empty() &&
      (*codes)[0].is_string()) {
    result.error = (*codes)[0].get<std::string>();
  }
  return result;
}

Captcha::Captcha(CaptchaSettings settings, const Challenger* challenger)
    : settings_(std::move(settings)), challenger_(challenger) {
  if (settings_.provider == CaptchaProvider::kTurnstile ||
      settings_.provider == CaptchaProvider::kHcaptcha ||
      settings_.provider == CaptchaProvider::kRecaptcha) {
    if (settings_.verify_url.empty()) {
      settings_.verify_url =
          settings_.provider == CaptchaProvider::kTurnstile
              ? "https://challenges.cloudflare.com/turnstile/v0/siteverify"
          : settings_.provider == CaptchaProvider::kHcaptcha
              ? "https://api.hcaptcha.com/siteverify"
              : "https://www.google.com/recaptcha/api/siteverify";
    }
    for (int i = 0; i < std::max(1, settings_.threads); ++i) {
      threads_.emplace_back([this](const std::stop_token& stop) { Run(stop); });
    }
  }
}

Captcha::~Captcha() {
  for (std::jthread& thread : threads_) thread.request_stop();
  wake_.notify_all();
}

std::string Captcha::NewRound(const ClientBinding& binding,
                              std::string_view return_path, int round,
                              int64_t now_ms, std::string* image,
                              std::string* sample) const {
  uint64_t seed = 0;
  if (settings_.test_seed != 0) {
    seed = settings_.test_seed + next_test_seed_.fetch_add(1);
  } else {
    RAND_bytes(reinterpret_cast<uint8_t*>(&seed), sizeof(seed));
  }
  const Puzzle puzzle = GeneratePuzzle(seed);
  *image = PngDataUri(puzzle.image_png);
  *sample = PngDataUri(puzzle.sample_png);
  PuzzleClaims claims;
  claims.issued_ms = now_ms;
  claims.round = round;
  claims.binding = binding;
  claims.x = puzzle.x;
  claims.y = puzzle.y;
  claims.radius = puzzle.radius;
  claims.return_path =
      IsSafeReturnPath(return_path) ? std::string(return_path) : "/";
  return SealPuzzle(challenger_->keys(), claims);
}

std::string Captcha::Page(const ClientBinding& binding,
                          std::string_view return_path, int64_t now_ms) const {
  const std::string safe_return =
      IsSafeReturnPath(return_path) ? std::string(return_path) : "/";
  if (settings_.provider == CaptchaProvider::kBuiltin) {
    std::string image;
    std::string sample;
    const std::string nonce =
        NewRound(binding, safe_return, 1, now_ms, &image, &sample);
    return GatewayPage(
        "One more check",
        std::format(
            "<noscript>JavaScript is required to continue.</noscript>"
            "<h3>One more check</h3>"
            "<p>Click the shape in the picture that matches this one:</p>"
            "<img id=\"bs-s\" src=\"{}\" width=\"100\" height=\"100\" "
            "alt=\"sample\" draggable=\"false\">"
            "<p><img id=\"bs-p\" src=\"{}\" width=\"300\" height=\"200\" "
            "alt=\"puzzle\" draggable=\"false\"></p>"
            "<p><small>Round <span id=\"bs-round\">1 / {}</span> &middot; "
            "<a href=\"/__bs/captcha?r={}\">another picture</a></small></p>"
            "<p id=\"bs-status\" aria-live=\"polite\"></p><script>"
            "(function(){{var N=\"{}\",D={};{}{}{}}})();</script>",
            sample, image, settings_.rounds, PercentEncode(safe_return), nonce,
            settings_.difficulty, CryptoJs(), ProbesJs(), PuzzleJs()));
  }
  NonceClaims claims;
  claims.issued = now_ms / 1000;
  claims.difficulty = settings_.difficulty;
  claims.binding = binding;
  claims.return_path = safe_return;
  const std::string nonce = IssueNonce(challenger_->keys(), claims, "w1");
  const std::string key = HtmlEscape(settings_.site_key);
  std::string widget;
  switch (settings_.provider) {
    case CaptchaProvider::kTurnstile:
      widget = std::format(
          "<script src=\"https://challenges.cloudflare.com/turnstile/v0/"
          "api.js\" async defer></script><div class=\"cf-turnstile\" "
          "data-sitekey=\"{}\" data-callback=\"bsCaptchaDone\" "
          "data-action=\"larpguard\" data-cdata=\"{}\"></div>",
          key, Sha256Hex(nonce, 32));
      break;
    case CaptchaProvider::kHcaptcha:
      widget = std::format(
          "<script src=\"https://js.hcaptcha.com/1/api.js\" async defer>"
          "</script><div class=\"h-captcha\" data-sitekey=\"{}\" "
          "data-callback=\"bsCaptchaDone\"></div>",
          key);
      break;
    default:
      widget = std::format(
          "<script src=\"https://www.google.com/recaptcha/api.js\" async "
          "defer></script><div class=\"g-recaptcha\" data-sitekey=\"{}\" "
          "data-callback=\"bsCaptchaDone\"></div>",
          key);
      break;
  }
  return GatewayPage(
      "One more check",
      std::format("<noscript>JavaScript is required to continue.</noscript>"
                  "<h3>One more check</h3><p>Please confirm you are human."
                  "</p><div style=\"display:inline-block\">{}</div>"
                  "<p id=\"bs-status\" aria-live=\"polite\"></p><script>"
                  "(function(){{var N=\"{}\",D={};{}{}{}}})();</script>",
                  widget, nonce, settings_.difficulty, CryptoJs(), ProbesJs(),
                  WidgetJs()));
}

bool Captcha::Used(const std::string& key, int64_t now_ms) {
  const std::scoped_lock lock(mutex_);
  // Swept when it grows; the endpoint rate limit bounds the growth.
  if (used_.size() >= 100000) {
    std::erase_if(
        used_, [now_ms](const auto& entry) { return entry.second <= now_ms; });
    if (used_.size() >= 100000) used_.clear();
  }
  const int64_t expires =
      now_ms + std::chrono::duration_cast<std::chrono::milliseconds>(
                   settings_.page_max_age)
                   .count();
  return !used_.try_emplace(key, expires).second;
}

Captcha::Answer Captcha::AnswerPuzzle(std::string_view query,
                                      const ClientBinding& binding,
                                      std::string_view user_agent,
                                      int64_t now_ms) {
  Answer answer;
  const QueryParams params = ParseQuery(query);
  const std::string nonce = QueryParam(params, "n");
  const auto fail = [&answer](std::string_view why, std::string_view message) {
    answer.outcome = std::format("failed:{}", why);
    answer.body = Json({{"message", message}});
    return answer;
  };
  PuzzleClaims claims;
  if (settings_.provider != CaptchaProvider::kBuiltin ||
      !OpenPuzzle(challenger_->keys(), nonce, &claims)) {
    return fail("bad_nonce", "This check expired. Reload the page.");
  }
  if (!(claims.binding == binding)) {
    return fail("binding", "This check expired. Reload the page.");
  }
  if (Used(nonce, now_ms)) {
    return fail("replay", "This check expired. Reload the page.");
  }
  if (!PowOk(nonce, QueryParam(params, "c"), settings_.difficulty)) {
    return fail("pow", "Something went wrong. Reload the page.");
  }
  const SignalCheck check =
      CheckSignals(DecodeJson(QueryParam(params, "s")), user_agent);
  answer.client_fp = check.client_fp;
  if (!check.fatal.empty()) {
    return fail(check.fatal, "We could not verify your browser.");
  }
  int64_t x = -1;
  int64_t y = -1;
  ParseInt(QueryParam(params, "x"), &x);
  ParseInt(QueryParam(params, "y"), &y);
  const std::string_view pointer =
      CheckPointer(DecodeJson(QueryParam(params, "m")), static_cast<int>(x),
                   static_cast<int>(y));
  if (!pointer.empty()) {
    return fail(pointer, "We could not verify your browser.");
  }

  const int64_t elapsed = now_ms - claims.issued_ms;
  const auto another = [&](std::string_view why, std::string_view message) {
    std::string image;
    std::string sample;
    const std::string next =
        NewRound(binding, claims.return_path, 1, now_ms, &image, &sample);
    answer.outcome = std::format("retry:{}", why);
    answer.body =
        Json({{"message", message},
              {"next",
               {{"n", next},
                {"image", image},
                {"sample", sample},
                {"round", std::format("1 / {}", settings_.rounds)}}}});
    return answer;
  };
  if (elapsed < settings_.min_answer.count()) {
    return another("too_fast", "Too quick. Try this one.");
  }
  if (elapsed > std::chrono::duration_cast<std::chrono::milliseconds>(
                    settings_.round_timeout)
                    .count()) {
    return another("too_slow", "That took too long. Try this one.");
  }
  if (std::hypot(static_cast<double>(x - claims.x),
                 static_cast<double>(y - claims.y)) > claims.radius * 1.2 + 3) {
    return another("wrong", "That was not it. Try this one.");
  }
  if (claims.round < settings_.rounds) {
    std::string image;
    std::string sample;
    const std::string next = NewRound(
        binding, claims.return_path, claims.round + 1, now_ms, &image, &sample);
    answer.outcome = "next";
    answer.body = Json({{"message", "Correct. One more."},
                        {"next",
                         {{"n", next},
                          {"image", image},
                          {"sample", sample},
                          {"round", std::format("{} / {}", claims.round + 1,
                                                settings_.rounds)}}}});
    return answer;
  }
  answer.outcome = "passed";
  answer.set_cookie =
      challenger_->ClearanceCookie(binding, kTokenLevelCaptcha, now_ms / 1000);
  answer.body = Json({{"done", claims.return_path}});
  return answer;
}

bool Captcha::VerifyWidget(std::string_view query, const ClientBinding& binding,
                           std::string_view user_agent, std::string_view host,
                           std::string_view remote_ip, int64_t now_ms,
                           Verdict* immediate,
                           std::function<void(Verdict)> done) {
  const QueryParams params = ParseQuery(query);
  const std::string nonce = QueryParam(params, "n");
  const std::string token = QueryParam(params, "t");
  const auto fail = [immediate](std::string_view why) {
    immediate->passed = false;
    immediate->reason = std::format("failed:{}", why);
    return false;
  };
  NonceClaims claims;
  if (settings_.provider == CaptchaProvider::kBuiltin ||
      settings_.provider == CaptchaProvider::kNone ||
      !VerifyNonce(challenger_->keys(), nonce, now_ms / 1000,
                   settings_.page_max_age.count(), &claims, "w1")) {
    return fail("bad_nonce");
  }
  immediate->return_path = claims.return_path;
  if (!(claims.binding == binding)) return fail("binding");
  if (!PowOk(nonce, QueryParam(params, "c"), claims.difficulty)) {
    return fail("pow");
  }
  const SignalCheck check =
      CheckSignals(DecodeJson(QueryParam(params, "s")), user_agent);
  immediate->client_fp = check.client_fp;
  if (!check.fatal.empty()) return fail(check.fatal);
  if (token.empty() || token.size() > 4096) return fail("no_token");
  if (Used(nonce, now_ms) || Used("t|" + token, now_ms)) {
    return fail("replay");
  }
  Job job;
  job.token = token;
  job.remote_ip = std::string(remote_ip);
  job.host = std::string(host);
  job.cdata = Sha256Hex(nonce, 32);
  job.verdict.return_path = claims.return_path;
  job.verdict.client_fp = check.client_fp;
  job.binding = binding;
  job.now = now_ms / 1000;
  job.done = std::move(done);
  {
    const std::scoped_lock lock(mutex_);
    if (queue_.size() >= settings_.max_queue) return fail("busy");
    queue_.push_back(std::move(job));
  }
  wake_.notify_one();
  return true;
}

Captcha::Verdict Captcha::Siteverify(const Job& job,
                                     const std::stop_token& stop) const {
  Verdict verdict = job.verdict;
  HttpClientRequest request;
  request.stop = stop;
  request.method = "POST";
  request.url = settings_.verify_url;
  request.max_redirects = 0;
  request.timeout = settings_.provider_timeout;
  request.max_body = std::size_t{64} << 10;
  request.headers = {{"Content-Type", "application/x-www-form-urlencoded"}};
  request.body = std::format(
      "secret={}&response={}&remoteip={}", PercentEncode(settings_.secret),
      PercentEncode(job.token), PercentEncode(job.remote_ip));
  if (settings_.provider == CaptchaProvider::kHcaptcha) {
    request.body += "&sitekey=" + PercentEncode(settings_.site_key);
  }
  HttpClientResponse response;
  std::string error;
  if (!HttpFetch(request, &response, &error) || response.status != 200) {
    verdict.reason = "failed:provider_unreachable";
    return verdict;
  }
  const SiteverifyResult result = ParseSiteverify(response.body);
  if (!result.success) {
    verdict.reason = std::format(
        "failed:provider:{}", result.error.empty() ? "rejected" : result.error);
    return verdict;
  }
  if (settings_.check_hostname && !result.hostname.empty() &&
      result.hostname != job.host) {
    verdict.reason = "failed:hostname";
    return verdict;
  }
  if (settings_.provider == CaptchaProvider::kTurnstile &&
      result.cdata != job.cdata) {
    verdict.reason = "failed:cdata";
    return verdict;
  }
  if (result.challenge_ts != 0 &&
      std::abs(job.now - result.challenge_ts) > kChallengeTsWindow) {
    verdict.reason = "failed:stale";
    return verdict;
  }
  verdict.passed = true;
  verdict.reason = "passed";
  verdict.set_cookie =
      challenger_->ClearanceCookie(job.binding, kTokenLevelCaptcha, job.now);
  return verdict;
}

void Captcha::WaitIdle() {
  std::unique_lock lock(mutex_);
  idle_.wait(lock, [this] { return queue_.empty() && running_ == 0; });
}

void Captcha::Run(const std::stop_token& stop) {
  while (true) {
    Job job;
    {
      std::unique_lock lock(mutex_);
      if (!wake_.wait(lock, stop, [this] { return !queue_.empty(); })) return;
      job = std::move(queue_.front());
      queue_.pop_front();
      ++running_;
    }
    Verdict verdict = Siteverify(job, stop);
    job.done(std::move(verdict));
    {
      const std::scoped_lock lock(mutex_);
      --running_;
    }
    idle_.notify_all();
  }
}

}  // namespace bot_shield
