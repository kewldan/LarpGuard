#include "fp/user_agent.h"

#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <string>
#include <string_view>

namespace bot_shield {
namespace {

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

// Version number right after `token` ("Chrome/" -> 120), or 0.
int MajorAfter(std::string_view text, std::string_view token) {
  const std::size_t at = text.find(token);
  if (at == std::string_view::npos) return 0;
  const std::string_view rest = text.substr(at + token.size());
  int major = 0;
  std::from_chars(rest.data(), rest.data() + rest.size(), major);
  return major;
}

bool Contains(std::string_view text, std::string_view token) {
  return text.find(token) != std::string_view::npos;
}

// HTTP libraries and tools, matched case-insensitively.
constexpr std::array<std::string_view, 24> kTools = {
    "curl/",
    "wget/",
    "python-requests/",
    "python-urllib/",
    "python-httpx/",
    "httpx/",
    "aiohttp/",
    "go-http-client/",
    "okhttp/",
    "java/",
    "apache-httpclient/",
    "node-fetch/",
    "undici",
    "axios/",
    "libwww-perl/",
    "scrapy/",
    "phantomjs",
    "httpie/",
    "powershell/",
    "postmanruntime/",
    "insomnia/",
    "guzzlehttp/",
    "ruby",
    "dart:io",
};

// "bot" only in the forms crawlers use (Googlebot/2.1, AhrefsBot;,
// some-bot): a bare "bot" also matches phone models such as "CUBOT".
constexpr std::array<std::string_view, 10> kCrawlerTokens = {
    "bot/", "bot;",    "bot)",   "-bot",  "bot-",
    "_bot", "crawler", "spider", "slurp", "facebookexternalhit"};

struct BrowserMarker {
  std::string_view token;
  std::string_view family;
  // The marker carries the browser's own version; take Chrome's instead.
  bool chrome_version;
};

constexpr std::array<BrowserMarker, 8> kBrowserMarkers = {{
    {"Edg/", "edge", false},
    {"OPR/", "opera", true},
    {"SamsungBrowser/", "samsung", true},
    {"CriOS/", "chrome", false},
    {"FxiOS/", "firefox", false},
    {"Firefox/", "firefox", false},
    {"HeadlessChrome/", "chrome", false},
    {"Chrome/", "chrome", false},
}};

}  // namespace

UserAgent ParseUserAgent(std::string_view user_agent) {
  UserAgent ua;
  if (user_agent.empty()) return ua;
  const std::string lower = Lowercase(user_agent);

  for (std::string_view tool : kTools) {
    const std::string spaced = " " + std::string(tool);
    if (lower.starts_with(tool) || Contains(lower, spaced)) {
      std::string name(tool);
      if (name.ends_with('/')) name.pop_back();
      ua.tool = name;
      break;
    }
  }
  if (ua.tool.empty()) {
    for (std::string_view token : kCrawlerTokens) {
      if (Contains(lower, token)) {
        ua.claims_crawler = true;
        break;
      }
    }
  }

  if (Contains(user_agent, "iPhone") || Contains(user_agent, "iPad") ||
      Contains(user_agent, "iPod")) {
    ua.os = "ios";
  } else if (Contains(user_agent, "Android")) {
    ua.os = "android";
  } else if (Contains(user_agent, "Windows NT")) {
    ua.os = "windows";
  } else if (Contains(user_agent, "CrOS")) {
    ua.os = "chromeos";
  } else if (Contains(user_agent, "Macintosh") ||
             Contains(user_agent, "Mac OS X")) {
    ua.os = "macos";
  } else if (Contains(user_agent, "Linux")) {
    ua.os = "linux";
  }
  ua.mobile =
      Contains(user_agent, "Mobile") || ua.os == "android" || ua.os == "ios";
  ua.headless = Contains(user_agent, "HeadlessChrome");

  // First match wins: Chromium-based browsers also say "Chrome/" and
  // "Safari/", so the specific markers come first.
  for (const BrowserMarker& marker : kBrowserMarkers) {
    const int major = MajorAfter(user_agent, marker.token);
    if (major <= 0) continue;
    ua.family = marker.family;
    ua.major =
        marker.chrome_version ? MajorAfter(user_agent, "Chrome/") : major;
    break;
  }
  if (ua.family.empty() && Contains(user_agent, "Safari/")) {
    const int major = MajorAfter(user_agent, "Version/");
    if (major > 0) {
      ua.family = "safari";
      ua.major = major;
    }
  }

  if (!ua.family.empty() && ua.tool.empty()) {
    // Every iOS browser runs on WebKit and Apple's network stack.
    if (ua.os == "ios" || ua.family == "safari") {
      ua.engine = "webkit";
    } else if (ua.family == "firefox") {
      ua.engine = "firefox";
    } else {
      ua.engine = "chromium";
    }
  }
  return ua;
}

}  // namespace bot_shield
