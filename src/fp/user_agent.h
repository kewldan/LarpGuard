#ifndef BOT_SHIELD_FP_USER_AGENT_H_
#define BOT_SHIELD_FP_USER_AGENT_H_

#include <string>
#include <string_view>

namespace bot_shield {

// What a User-Agent string claims. Only the parts the consistency checks
// need; not a general-purpose UA parser.
struct UserAgent {
  // "chrome", "edge", "opera", "samsung", "firefox", "safari" or "".
  std::string family;
  // Engine whose network stack the claim implies: "chromium", "firefox",
  // "webkit" (Safari and every browser on iOS) or "".
  std::string engine;
  int major = 0;
  // "windows", "macos", "linux", "chromeos", "android", "ios" or "".
  std::string os;
  bool mobile = false;
  bool headless = false;
  // HTTP library or tool ("curl", "python-requests", ...) or "".
  std::string tool;
  // Says it is a crawler (Googlebot, "bot", "spider", ...). Unverified.
  bool claims_crawler = false;
};

UserAgent ParseUserAgent(std::string_view user_agent);

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_USER_AGENT_H_
