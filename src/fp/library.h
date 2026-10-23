#ifndef BOT_SHIELD_FP_LIBRARY_H_
#define BOT_SHIELD_FP_LIBRARY_H_

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {

// What a real browser engine's network stack looks like.
struct BrowserProfile {
  std::string id;
  std::vector<std::string> engines;
  // JA4 part b (cipher hash) values; empty means "not checked".
  std::vector<std::string> ja4_ciphers;
  // HTTP/2 pseudo-header orders ("m,a,s,p"); empty means "not checked".
  std::vector<std::string> h2_pseudo_orders;
  // Major version from which the browser sends Sec-CH-UA (0: never).
  int client_hints_since = 0;
  // Major version from which it sends Sec-Fetch-* (0: never).
  int fetch_metadata_since = 0;
};

// A known automation client. Every non-empty field must match.
struct AutomationSignature {
  std::string id;
  int weight = 0;
  std::string ja4;             // Glob.
  std::string h2_fingerprint;  // Glob.
  std::string header_fp;       // Glob.
  std::string user_agent;      // Case-insensitive substring.
};

// The fingerprint library: browser profiles, automation signatures and
// signal weights. Loaded once at startup.
class FingerprintLibrary {
 public:
  // The library compiled into the binary (deploy/fingerprints.yaml).
  static const FingerprintLibrary& BuiltIn();
  static std::string_view BuiltInYaml();

  static bool Parse(std::string_view yaml, FingerprintLibrary* library,
                    std::string* error);
  static bool Load(const std::string& path, FingerprintLibrary* library,
                   std::string* error);

  const BrowserProfile* ProfileForEngine(std::string_view engine) const;
  // The browser whose cipher suites hash to `ciphers` (JA4 part b).
  const BrowserProfile* ProfileForJa4Ciphers(std::string_view ciphers) const;
  const std::vector<AutomationSignature>& automation() const {
    return automation_;
  }
  // Weight of a signal; 0 for unknown names.
  int Weight(std::string_view signal) const;
  const std::map<std::string, int, std::less<>>& weights() const {
    return weights_;
  }
  const std::string& version() const { return version_; }
  std::size_t profile_count() const { return browsers_.size(); }

 private:
  std::string version_;
  std::vector<BrowserProfile> browsers_;
  std::vector<AutomationSignature> automation_;
  std::map<std::string, int, std::less<>> weights_;
};

// Shell-style match with '*' only (any run of characters).
bool GlobMatch(std::string_view pattern, std::string_view text);

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_LIBRARY_H_
