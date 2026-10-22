#include "fp/library.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield {
namespace {

// Kept identical to deploy/fingerprints.yaml (a unit test checks it).
constexpr std::string_view kBuiltInYaml =
    R"yaml(# bot-shield fingerprint library.
#
# Built into the binary; point fingerprints.library at a copy of this file to
# change it. Values come from published specifications and the browsers'
# cipher suite lists (JA4 cipher hashes were recomputed from them). Extend
# the library from the fp_hourly clusters in ClickHouse.
version: 2026-10-22

# Network stacks of real browsers, by the engine a User-Agent implies. A
# client claiming an engine but showing another stack is the main signal.
browsers:
  - id: chromium
    engines: [chromium]
    # JA4 part b: Chrome's 15 cipher suites (t13d15..).
    ja4_ciphers: [8daaf6152771]
    h2_pseudo_orders: ["m,a,s,p"]
    client_hints_since: 89
    fetch_metadata_since: 76
  - id: firefox
    engines: [firefox]
    ja4_ciphers: [5b57614c22b0]
    h2_pseudo_orders: ["m,p,a,s"]
    client_hints_since: 0
    fetch_metadata_since: 90
  - id: webkit
    engines: [webkit]
    ja4_ciphers: [a09f3c656075]
    h2_pseudo_orders: ["m,s,p,a", "m,s,a,p"]
    client_hints_since: 0
    # Safari sends Sec-Fetch-* since 16.4; iOS browsers report their own
    # version numbers, which are all above 16 by now.
    fetch_metadata_since: 17

# Known automation, matched on top of the checks above. Every non-empty field
# must match; ja4, h2_fingerprint and header_fp accept '*' wildcards,
# user_agent is a case-insensitive substring.
automation: []
#  - id: example-scraper
#    weight: 60
#    ja4: "t13d1812h1_*"
#    h2_fingerprint: ""
#    header_fp: ""
#    user_agent: ""

# Score added by each signal (the total is capped at 100).
weights:
  empty_user_agent: 60
  automation_user_agent: 80
  headless_user_agent: 80
  unverified_crawler: 20
  fake_crawler: 70
  ua_tls_mismatch: 45
  ua_h2_mismatch: 35
  browser_without_h2: 25
  missing_client_hints: 25
  missing_fetch_metadata: 25
  missing_accept_language: 15
  os_tcp_mismatch: 20
  # Honeypot (docs/architecture.md 6.3): the trap request itself, and later
  # requests from the same address or fingerprint+network.
  honeypot: 100
  honeypot_client: 70
  # Behaviour over a window (5.4).
  behavior_regular_timing: 30
  behavior_not_found: 30
  behavior_api_without_page: 20
  behavior_no_assets: 25
  behavior_sequential_ids: 35
  # Model signal (gradient-boosted trees, model.threshold).
  model: 30
  # Client network from the ASN database (asn.url): clouds and hosters,
  # where real browsers are mostly VPNs and proxies.
  hosting_network: 10
  # A Web Bot Auth signature (web_bot_auth) that does not verify.
  web_bot_auth_invalid: 40
  # The TLS 1.3 handshake takes far longer than the kernel's TCP round
  # trip: the TLS client sits behind a TCP relay (residential and SOCKS
  # proxies; also satellite links and carrier TCP accelerators, hence the
  # modest weight).
  relayed_connection: 15
)yaml";

std::vector<std::string> ReadList(const YAML::Node& node) {
  std::vector<std::string> out;
  if (!node) return out;
  for (const auto& item : node) out.push_back(item.as<std::string>());
  return out;
}

std::string ReadString(const YAML::Node& node, const char* key) {
  return node[key] ? node[key].as<std::string>() : std::string();
}

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

}  // namespace

bool GlobMatch(std::string_view pattern, std::string_view text) {
  // Iterative matcher with backtracking to the last '*'.
  std::size_t p = 0;
  std::size_t t = 0;
  std::size_t star = std::string_view::npos;
  std::size_t mark = 0;
  while (t < text.size()) {
    if (p < pattern.size() && pattern[p] == '*') {
      star = p++;
      mark = t;
    } else if (p < pattern.size() && pattern[p] == text[t]) {
      ++p;
      ++t;
    } else if (star != std::string_view::npos) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.size() && pattern[p] == '*') ++p;
  return p == pattern.size();
}

std::string_view FingerprintLibrary::BuiltInYaml() { return kBuiltInYaml; }

const FingerprintLibrary& FingerprintLibrary::BuiltIn() {
  static const FingerprintLibrary kLibrary = [] {
    FingerprintLibrary parsed;
    std::string error;
    if (!Parse(kBuiltInYaml, &parsed, &error)) {
      // A broken built-in library is a build defect; tests catch it.
      parsed = FingerprintLibrary{};
    }
    return parsed;
  }();
  return kLibrary;
}

bool FingerprintLibrary::Parse(std::string_view yaml,
                               FingerprintLibrary* library,
                               std::string* error) {
  try {
    const YAML::Node root = YAML::Load(std::string(yaml));
    if (!root.IsMap()) {
      *error = "fingerprint library: expected a mapping";
      return false;
    }
    FingerprintLibrary out;
    out.version_ = ReadString(root, "version");
    for (const auto& node : root["browsers"]) {
      BrowserProfile profile;
      profile.id = ReadString(node, "id");
      profile.engines = ReadList(node["engines"]);
      profile.ja4_ciphers = ReadList(node["ja4_ciphers"]);
      profile.h2_pseudo_orders = ReadList(node["h2_pseudo_orders"]);
      if (node["client_hints_since"]) {
        profile.client_hints_since = node["client_hints_since"].as<int>();
      }
      if (node["fetch_metadata_since"]) {
        profile.fetch_metadata_since = node["fetch_metadata_since"].as<int>();
      }
      if (profile.id.empty() || profile.engines.empty()) {
        *error = "fingerprint library: browser needs id and engines";
        return false;
      }
      out.browsers_.push_back(std::move(profile));
    }
    for (const auto& node : root["automation"]) {
      AutomationSignature signature;
      signature.id = ReadString(node, "id");
      signature.weight = node["weight"] ? node["weight"].as<int>() : 0;
      signature.ja4 = ReadString(node, "ja4");
      signature.h2_fingerprint = ReadString(node, "h2_fingerprint");
      signature.header_fp = ReadString(node, "header_fp");
      signature.user_agent = Lowercase(ReadString(node, "user_agent"));
      if (signature.id.empty() ||
          (signature.ja4.empty() && signature.h2_fingerprint.empty() &&
           signature.header_fp.empty() && signature.user_agent.empty())) {
        *error = "fingerprint library: automation entry needs id and a match";
        return false;
      }
      out.automation_.push_back(std::move(signature));
    }
    for (const auto& item : root["weights"]) {
      out.weights_[item.first.as<std::string>()] = item.second.as<int>();
    }
    *library = std::move(out);
    return true;
  } catch (const YAML::Exception& e) {
    *error = std::format("fingerprint library: {}", e.what());
    return false;
  }
}

bool FingerprintLibrary::Load(const std::string& path,
                              FingerprintLibrary* library, std::string* error) {
  std::ifstream file(path);
  if (!file) {
    *error = std::format("cannot open {}", path);
    return false;
  }
  std::stringstream contents;
  contents << file.rdbuf();
  return Parse(contents.str(), library, error);
}

const BrowserProfile* FingerprintLibrary::ProfileForEngine(
    std::string_view engine) const {
  if (engine.empty()) return nullptr;
  for (const BrowserProfile& profile : browsers_) {
    if (std::ranges::find(profile.engines, engine) != profile.engines.end()) {
      return &profile;
    }
  }
  return nullptr;
}

int FingerprintLibrary::Weight(std::string_view signal) const {
  const auto it = weights_.find(signal);
  return it == weights_.end() ? 0 : it->second;
}

}  // namespace bot_shield
