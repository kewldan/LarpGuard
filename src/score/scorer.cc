#include "score/scorer.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fp/http_request.h"
#include "fp/library.h"
#include "fp/user_agent.h"

namespace bot_shield {
namespace {

// JA4 part b (sorted cipher hash): the text between the first two '_'.
std::string_view Ja4CipherHash(std::string_view ja4) {
  const auto first = ja4.find('_');
  if (first == std::string_view::npos) return {};
  const auto second = ja4.find('_', first + 1);
  if (second == std::string_view::npos) return {};
  return ja4.substr(first + 1, second - first - 1);
}

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

bool Contains(const std::vector<std::string>& values, std::string_view value) {
  return std::ranges::find(values, value) != values.end();
}

}  // namespace

std::string_view BotClassName(BotClass bot_class) {
  switch (bot_class) {
    case BotClass::kHuman:
      return "human";
    case BotClass::kSuspicious:
      return "suspicious";
    case BotClass::kBot:
      return "bot";
  }
  return "?";
}

Scorer::Scorer(const FingerprintLibrary* library, int suspicious_threshold,
               int bot_threshold)
    : library_(library),
      suspicious_threshold_(suspicious_threshold),
      bot_threshold_(bot_threshold) {}

Verdict Scorer::Score(const ScoringInput& input) const {
  Verdict verdict;
  int total = 0;
  const auto add = [&](std::string reason, int weight) {
    if (weight <= 0) return;
    total += weight;
    verdict.reasons.push_back(std::move(reason));
  };
  const auto signal = [&](std::string_view name) {
    add(std::string(name), library_->Weight(name));
  };

  const HttpRequest& request = *input.request;
  const std::string_view user_agent_text = request.Header("user-agent");
  const UserAgent ua = ParseUserAgent(user_agent_text);

  if (user_agent_text.empty()) signal("empty_user_agent");
  if (!ua.tool.empty()) signal("automation_user_agent");
  if (ua.headless) signal("headless_user_agent");
  if (ua.claims_crawler) signal("unverified_crawler");

  // The client claims a browser: its stack must look like that browser's.
  if (const BrowserProfile* profile = library_->ProfileForEngine(ua.engine)) {
    const bool tls = !input.ja4.empty();
    const std::string_view ciphers = Ja4CipherHash(input.ja4);
    if (tls && !profile->ja4_ciphers.empty() &&
        !Contains(profile->ja4_ciphers, ciphers)) {
      signal("ua_tls_mismatch");
    }
    if (tls && !input.offered_h2) signal("browser_without_h2");
    if (!input.pseudo_order.empty() && !profile->h2_pseudo_orders.empty() &&
        !Contains(profile->h2_pseudo_orders, input.pseudo_order)) {
      signal("ua_h2_mismatch");
    }
    if (profile->client_hints_since > 0 &&
        ua.major >= profile->client_hints_since &&
        !request.HasHeader("sec-ch-ua")) {
      signal("missing_client_hints");
    }
    if (profile->fetch_metadata_since > 0 &&
        ua.major >= profile->fetch_metadata_since &&
        !request.HasHeader("sec-fetch-mode")) {
      signal("missing_fetch_metadata");
    }
    if (!request.HasHeader("accept-language")) {
      signal("missing_accept_language");
    }
    // Windows starts TTLs at 128, Linux/macOS/Android/iOS at 64.
    if (input.tcp_initial_ttl != 0) {
      const bool windows_stack = input.tcp_initial_ttl == 128;
      if ((ua.os == "windows" && !windows_stack) ||
          (!ua.os.empty() && ua.os != "windows" && windows_stack)) {
        signal("os_tcp_mismatch");
      }
    }
  }

  const std::string user_agent_lower = Lowercase(user_agent_text);
  for (const AutomationSignature& signature : library_->automation()) {
    const bool match =
        (signature.ja4.empty() || GlobMatch(signature.ja4, input.ja4)) &&
        (signature.h2_fingerprint.empty() ||
         GlobMatch(signature.h2_fingerprint, input.h2_fingerprint)) &&
        (signature.header_fp.empty() ||
         GlobMatch(signature.header_fp, input.header_fp)) &&
        (signature.user_agent.empty() ||
         user_agent_lower.find(signature.user_agent) != std::string::npos);
    if (match) add("known_automation:" + signature.id, signature.weight);
  }

  verdict.score = std::clamp(total, 0, 100);
  if (verdict.score >= bot_threshold_) {
    verdict.bot_class = BotClass::kBot;
  } else if (verdict.score >= suspicious_threshold_) {
    verdict.bot_class = BotClass::kSuspicious;
  }
  return verdict;
}

}  // namespace bot_shield
