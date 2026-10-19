#include "challenge/challenger.h"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "challenge/scripts.h"
#include "challenge/token.h"
#include "common/hash.h"
#include "common/url.h"
#include "fp/http_request.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

std::string Lower(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

int IntField(const nlohmann::json& object, const char* key, int fallback) {
  const auto it = object.find(key);
  return it != object.end() && it->is_number_integer() ? it->get<int>()
                                                       : fallback;
}

std::string StringField(const nlohmann::json& object, const char* key) {
  const auto it = object.find(key);
  return it != object.end() && it->is_string() ? it->get<std::string>()
                                               : std::string();
}

bool BoolField(const nlohmann::json& object, const char* key) {
  const auto it = object.find(key);
  return it != object.end() &&
         ((it->is_boolean() && it->get<bool>()) ||
          (it->is_number_integer() && it->get<int>() != 0));
}

// Renderers of headless and virtual machines (no GPU).
constexpr std::array<std::string_view, 8> kSoftwareRenderers = {
    "swiftshader",    "llvmpipe",     "softpipe",   "lavapipe",
    "mesa offscreen", "basic render", "virtualbox", "vmware"};

}  // namespace

SignalCheck CheckSignals(const nlohmann::json& signals,
                         std::string_view user_agent) {
  SignalCheck check;
  if (!signals.is_object()) {
    check.fatal = "signals";
    return check;
  }
  // Fatal: the browser says it is automated.
  if (BoolField(signals, "wd")) {
    check.fatal = "webdriver";
  } else if (BoolField(signals, "ph")) {
    check.fatal = "automation_globals";
  } else if (const auto brands = signals.find("brands");
             brands != signals.end() && brands->is_array()) {
    for (const auto& brand : *brands) {
      if (brand.is_string() &&
          brand.get<std::string>().find("Headless") != std::string::npos) {
        check.fatal = "headless";
      }
    }
  }
  // Suspicious: driven over the DevTools protocol, or spoofed.
  const std::string ua_hash = StringField(signals, "ua");
  if (BoolField(signals, "cdp")) {
    check.suspicious = "cdp";
  } else if (IntField(signals, "wm", 0) > 0) {
    check.suspicious = "worker_mismatch";
  } else if (!ua_hash.empty() && ua_hash != Sha256Hex(user_agent, 16)) {
    check.suspicious = "ua_mismatch";
  } else if (IntField(signals, "nt", 0) > 0) {
    check.suspicious = "tampered_natives";
  } else if (IntField(signals, "lang", 1) == 0) {
    check.suspicious = "no_languages";
  }
  // Soft: unusual environments.
  const std::string renderer = Lower(StringField(signals, "glr"));
  for (const std::string_view software : kSoftwareRenderers) {
    if (renderer.find(software) != std::string::npos) {
      check.soft.emplace_back("software_renderer");
      break;
    }
  }
  if (const auto screen = signals.find("sc");
      screen != signals.end() && screen->is_array() && screen->size() >= 8) {
    const auto at = [&screen](std::size_t i) {
      return (*screen)[i].is_number_integer() ? (*screen)[i].get<int>() : -1;
    };
    if (at(0) == 0 || at(1) == 0 || at(6) == 0 || at(7) == 0) {
      check.soft.emplace_back("headless_screen");
    }
  }
  if (signals.contains("cv")) {
    if (StringField(signals, "cv").empty()) {
      check.soft.emplace_back("canvas_blocked");
    } else if (IntField(signals, "cvn", 0) != 0) {
      check.soft.emplace_back("canvas_noise");
    }
  }
  const bool desktop =
      user_agent.find("Windows NT") != std::string_view::npos ||
      user_agent.find("Macintosh") != std::string_view::npos;
  if (desktop && IntField(signals, "fn", -1) == 0) {
    check.soft.emplace_back("no_fonts");
  }
  if (desktop && user_agent.find("Chrome/") != std::string_view::npos &&
      IntField(signals, "pl", -1) == 0) {
    check.soft.emplace_back("no_plugins");
  }
  if (signals.contains("cv")) {
    check.client_fp = Sha256Hex(
        std::format("{}|{}|{}|{}|{}", StringField(signals, "cv"), renderer,
                    StringField(signals, "glp"), StringField(signals, "au"),
                    StringField(signals, "fm")),
        16);
  }
  return check;
}

bool IsNavigation(const HttpRequest& request) {
  if (request.method != "GET" && request.method != "HEAD") return false;
  const std::string_view mode = request.Header("sec-fetch-mode");
  if (!mode.empty()) return mode == "navigate";
  return request.Header("accept").find("text/html") != std::string_view::npos;
}

std::string GatewayPage(std::string_view title, std::string_view body) {
  return std::format(
      "<!doctype html><html><head><meta charset=\"utf-8\">"
      "<meta name=\"robots\" content=\"noindex\">"
      "<meta name=\"viewport\" content=\"width=device-width\">"
      "<title>{}</title><style>body{{font:16px system-ui,sans-serif;"
      "display:flex;align-items:center;justify-content:center;"
      "min-height:100vh;margin:0;color:#333;background:#fafafa}}"
      "main{{max-width:340px;padding:24px;text-align:center}}"
      "img{{max-width:100%;border-radius:6px;user-select:none}}"
      "#bs-p{{cursor:crosshair;touch-action:manipulation}}"
      "small{{color:#777}}</style></head><body><main>{}</main></body></html>",
      title, body);
}

std::string ChallengeFailedPage() {
  return GatewayPage("Access denied",
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
  return GatewayPage(
      "Checking your browser",
      std::format("<noscript>JavaScript is required to continue.</noscript>"
                  "<p>Checking your browser&hellip;</p><script>"
                  "(function(){{var N=\"{}\",D={};{}{}{}}})();</script>",
                  nonce, difficulty, CryptoJs(), ProbesJs(), ChallengeJs()));
}

Challenger::Result Challenger::Verify(std::string_view query,
                                      const ClientBinding& binding,
                                      std::string_view user_agent,
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
  const SignalCheck check = CheckSignals(signals, user_agent);
  result.client_fp = check.client_fp;
  if (!check.fatal.empty()) {
    result.reason = check.fatal;
    return result;
  }
  if (!check.suspicious.empty()) {
    result.reason = check.suspicious;
    result.escalate = true;
    return result;
  }
  result.passed = true;
  result.soft = check.soft;
  result.escalate = !check.soft.empty();
  result.set_cookie = ClearanceCookie(binding, kTokenLevelJs, now);
  return result;
}

std::string Challenger::ClearanceCookie(const ClientBinding& binding, int level,
                                        int64_t now) const {
  TokenClaims token;
  token.issued = now;
  token.expires = now + settings_.token_ttl.count();
  token.binding = binding;
  token.level = level;
  return std::format(
      "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax", kCookieName,
      IssueToken(settings_.keys, token), settings_.token_ttl.count());
}

std::optional<Clearance> Challenger::FindClearance(const HttpRequest& request,
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
        const std::string_view token = field.substr(equals + 1);
        if (VerifyToken(settings_.keys, token, now, &claims) &&
            claims.binding == binding) {
          return Clearance{Sha256Hex(token, 16), claims.level};
        }
      }
      if (end == std::string_view::npos) break;
      rest.remove_prefix(end + 1);
    }
  }
  return std::nullopt;
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
