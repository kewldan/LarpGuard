#include "challenge/challenger.h"

#include <cstddef>
#include <cstdint>
#include <format>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "challenge/token.h"
#include "common/url.h"
#include "fp/http_request.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

// The page runs this script with N (nonce), D (difficulty) prepended. It
// collects a few browser signals, finds a counter whose SHA-256 has D
// leading zero bits (pure JS SHA-256: much faster than WebCrypto for many
// tiny inputs) and goes to /__bs/verify. No external resources.
constexpr std::string_view kScript = R"js(
function sha256(m) {
  var K = sha256.K, i;
  if (!K) {
    K = sha256.K = []; sha256.H = [];
    var frac = function (x) { return ((x - Math.floor(x)) * 4294967296) | 0; };
    for (var p = 2, n = 0; n < 64; p++) {
      var prime = true;
      for (var f = 2; f * f <= p; f++) if (p % f === 0) { prime = false; break; }
      if (!prime) continue;
      if (n < 8) sha256.H[n] = frac(Math.pow(p, 1 / 2));
      K[n++] = frac(Math.pow(p, 1 / 3));
    }
  }
  var H = sha256.H.slice(), l = m.length, bl = ((l + 9 + 63) >> 6) << 6;
  var w = new Uint8Array(bl), W = new Array(64), bits = l * 8;
  w.set(m); w[l] = 0x80;
  w[bl - 4] = (bits >>> 24) & 255; w[bl - 3] = (bits >>> 16) & 255;
  w[bl - 2] = (bits >>> 8) & 255; w[bl - 1] = bits & 255;
  for (var o = 0; o < bl; o += 64) {
    for (i = 0; i < 16; i++) {
      W[i] = (w[o + 4 * i] << 24) | (w[o + 4 * i + 1] << 16) |
             (w[o + 4 * i + 2] << 8) | w[o + 4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
      var x = W[i - 15], y = W[i - 2];
      var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f2 = H[5], g = H[6], h = H[7];
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var t1 = (h + S1 + ((e & f2) ^ (~e & g)) + K[i] + W[i]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f2; f2 = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0; H[5] = (H[5] + f2) | 0;
    H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  var out = new Uint8Array(32);
  for (i = 0; i < 8; i++) {
    out[4 * i] = H[i] >>> 24; out[4 * i + 1] = (H[i] >>> 16) & 255;
    out[4 * i + 2] = (H[i] >>> 8) & 255; out[4 * i + 3] = H[i] & 255;
  }
  return out;
}
function zeroBits(hash) {
  for (var bits = 0, i = 0; i < hash.length; i++) {
    if (hash[i] === 0) { bits += 8; continue; }
    for (var v = hash[i]; (v & 0x80) === 0; v <<= 1) bits++;
    break;
  }
  return bits;
}
function solve() {
  var prefix = new TextEncoder().encode(N + ":");
  for (var counter = 0; ; counter++) {
    var digits = String(counter), input = new Uint8Array(prefix.length + digits.length);
    input.set(prefix);
    for (var j = 0; j < digits.length; j++) input[prefix.length + j] = digits.charCodeAt(j);
    if (zeroBits(sha256(input)) >= D) return counter;
  }
}
function signals() {
  var n = navigator, uad = n.userAgentData;
  return {
    wd: !!n.webdriver,
    lang: (n.languages || []).length,
    hc: n.hardwareConcurrency || 0,
    plat: n.platform || "",
    brands: uad && uad.brands ? uad.brands.map(function (b) { return b.brand; }) : [],
    tz: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return ""; } })(),
    sw: (typeof screen !== "undefined" && screen.width) || 0,
    ph: !!(window.callPhantom || window._phantom || window.__nightmare)
  };
}
function b64url(text) {
  return btoa(unescape(encodeURIComponent(text)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
var started = Date.now(), counter = solve(), s = signals();
s.ms = Date.now() - started;
location.replace("/__bs/verify?n=" + encodeURIComponent(N) + "&c=" + counter +
                 "&s=" + b64url(JSON.stringify(s)));
)js";

std::string HtmlPage(std::string_view title, std::string_view body) {
  return std::format(
      "<!doctype html><html><head><meta charset=\"utf-8\">"
      "<meta name=\"robots\" content=\"noindex\">"
      "<meta name=\"viewport\" content=\"width=device-width\">"
      "<title>{}</title><style>body{{font:16px system-ui,sans-serif;"
      "display:flex;align-items:center;justify-content:center;height:100vh;"
      "margin:0;color:#333}}</style></head><body>{}</body></html>",
      title, body);
}

}  // namespace

bool IsNavigation(const HttpRequest& request) {
  if (request.method != "GET" && request.method != "HEAD") return false;
  const std::string_view mode = request.Header("sec-fetch-mode");
  if (!mode.empty()) return mode == "navigate";
  return request.Header("accept").find("text/html") != std::string_view::npos;
}

std::string ChallengeFailedPage() {
  return HtmlPage("Access denied",
                  "<p>We could not verify your browser. Enable JavaScript "
                  "and cookies, then reload the page.</p>");
}

int Challenger::DifficultyFor(BotClass bot_class) const {
  return bot_class == BotClass::kBot ? settings_.bot_difficulty
                                     : settings_.suspicious_difficulty;
}

std::string Challenger::Page(const ClientBinding& binding, int difficulty,
                             std::string_view return_path, int64_t now) const {
  NonceClaims claims;
  claims.issued = now;
  claims.difficulty = difficulty;
  claims.binding = binding;
  claims.return_path =
      IsSafeReturnPath(return_path) ? std::string(return_path) : "/";
  const std::string nonce = IssueNonce(settings_.keys, claims);
  // The nonce only holds [A-Za-z0-9._-]; it is safe inside a JS string.
  return HtmlPage(
      "Checking your browser",
      std::format("<noscript>JavaScript is required to continue.</noscript>"
                  "<p>Checking your browser&hellip;</p><script>"
                  "(function(){{var N=\"{}\",D={};{}}})();</script>",
                  nonce, difficulty, kScript));
}

Challenger::Result Challenger::Verify(std::string_view query,
                                      const ClientBinding& binding,
                                      int64_t now) const {
  Result result;
  const QueryParams params = ParseQuery(query);
  const std::string nonce = QueryParam(params, "n");
  NonceClaims claims;
  if (!VerifyNonce(settings_.keys, nonce, now, settings_.nonce_max_age.count(),
                   &claims)) {
    result.reason = "bad_nonce";
    return result;
  }
  result.return_path = claims.return_path;
  if (!(claims.binding == binding)) {
    result.reason = "binding";
    return result;
  }
  const std::string counter = QueryParam(params, "c");
  if (counter.empty() || counter.size() > 12 ||
      counter.find_first_not_of("0123456789") != std::string::npos ||
      PowZeroBits(nonce, counter) < claims.difficulty) {
    result.reason = "pow";
    return result;
  }
  std::string signals_text;
  const nlohmann::json signals =
      Base64UrlDecode(QueryParam(params, "s"), &signals_text)
          ? nlohmann::json::parse(signals_text, nullptr, false)
          : nlohmann::json();
  if (!signals.is_object()) {
    result.reason = "signals";
    return result;
  }
  if (signals.value("wd", false)) {
    result.reason = "webdriver";
    return result;
  }
  if (signals.value("ph", false)) {
    result.reason = "automation_globals";
    return result;
  }
  if (const auto brands = signals.find("brands");
      brands != signals.end() && brands->is_array()) {
    for (const auto& brand : *brands) {
      if (brand.is_string() &&
          brand.get<std::string>().find("Headless") != std::string::npos) {
        result.reason = "headless";
        return result;
      }
    }
  }
  if (signals.value("lang", 0) == 0) {
    result.reason = "no_languages";
    return result;
  }

  TokenClaims token;
  token.issued = now;
  token.expires = now + settings_.token_ttl.count();
  token.binding = binding;
  result.passed = true;
  result.set_cookie = std::format(
      "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax", kCookieName,
      IssueToken(settings_.keys, token), settings_.token_ttl.count());
  return result;
}

bool Challenger::HasValidToken(const HttpRequest& request,
                               const ClientBinding& binding,
                               int64_t now) const {
  for (const auto& [name, value] : request.headers) {
    if (name != "cookie") continue;
    std::string_view rest = value;
    while (!rest.empty()) {
      const std::size_t end = rest.find(';');
      std::string_view field = rest.substr(0, end);
      while (!field.empty() && field.front() == ' ') field.remove_prefix(1);
      const std::size_t equals = field.find('=');
      if (equals != std::string_view::npos &&
          field.substr(0, equals) == kCookieName) {
        TokenClaims claims;
        if (VerifyToken(settings_.keys, field.substr(equals + 1), now,
                        &claims) &&
            claims.binding == binding) {
          return true;
        }
      }
      if (end == std::string_view::npos) break;
      rest.remove_prefix(end + 1);
    }
  }
  return false;
}

std::string Challenger::StripCookie(std::string_view cookie_header) {
  std::string out;
  while (!cookie_header.empty()) {
    const std::size_t end = cookie_header.find(';');
    std::string_view field = cookie_header.substr(0, end);
    while (!field.empty() && field.front() == ' ') field.remove_prefix(1);
    if (!field.empty() && field.substr(0, field.find('=')) != kCookieName) {
      if (!out.empty()) out += "; ";
      out += field;
    }
    if (end == std::string_view::npos) break;
    cookie_header.remove_prefix(end + 1);
  }
  return out;
}

}  // namespace bot_shield
