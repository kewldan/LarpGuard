#include "server/whoami.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fp/library.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

std::string Capitalized(std::string_view text) {
  std::string out(text);
  if (!out.empty() && out[0] >= 'a' && out[0] <= 'z') {
    out[0] = static_cast<char>(out[0] - 'a' + 'A');
  }
  return out;
}

// The part of a reason after "prefix:", or "" when it has another prefix.
std::string_view AfterPrefix(std::string_view reason, std::string_view prefix) {
  return reason.starts_with(prefix) ? reason.substr(prefix.size())
                                    : std::string_view();
}

std::string_view FindReason(const WhoamiReport& report,
                            std::string_view prefix) {
  for (const auto& [reason, weight] : report.reasons) {
    const std::string_view rest = AfterPrefix(reason, prefix);
    if (!rest.empty()) return rest;
  }
  return {};
}

std::string_view ActionPhrase(std::string_view action) {
  if (action == "allow") return "let through";
  if (action == "block") return "blocked";
  if (action == "challenge") return "sent a JavaScript challenge";
  if (action == "captcha") return "shown a CAPTCHA";
  if (action == "throttle") return "throttled";
  if (action == "tarpit") return "tarpitted (a slow, endless response)";
  if (action == "decoy") return "served a decoy page";
  if (action == "rate_limit") return "rate-limited";
  return action;
}

std::string Claimed(const WhoamiReport& report) {
  if (report.claimed_family.empty()) return "";
  std::string text = Capitalized(report.claimed_family);
  if (report.claimed_major > 0) {
    text += std::format(" {}", report.claimed_major);
  }
  if (!report.claimed_os.empty()) text += " on " + report.claimed_os;
  return text;
}

std::string TtlText(int ttl) {
  if (ttl == 0) return "not captured";
  if (ttl == 128) return "128 (Windows)";
  if (ttl == 64) return "64 (Linux, macOS, Android or iOS)";
  return std::format("{}", ttl);
}

std::string Millis(int64_t micros) {
  return micros < 0
             ? std::string("?")
             : std::format("{:.1f} ms", static_cast<double>(micros) / 1000.0);
}

// TCP as the kernel measures it (to the nearest TCP stack) against the TLS
// handshake (to the TLS client).
std::string RoundTripText(const WhoamiReport& report) {
  std::string text =
      std::format("TCP {} · TLS handshake {}", Millis(report.tcp_rtt_us),
                  Millis(report.handshake_us));
  if (LooksRelayed(report.tcp_rtt_us, report.handshake_us)) {
    text += " (relayed: the TLS client is farther than the TCP peer)";
  }
  return text;
}

std::string NetworkText(const WhoamiReport& report) {
  std::string text = report.ip_prefix.empty() ? report.ip : report.ip_prefix;
  if (report.asn != 0) {
    text += std::format(" · AS{}", report.asn);
    if (!report.asn_org.empty()) text += " " + report.asn_org;
  }
  if (report.hosting) text += " · hosting or cloud network";
  return text;
}

std::string Joined(const std::vector<std::string>& values) {
  std::string out;
  for (const std::string& value : values) {
    if (!out.empty()) out += ", ";
    out += value;
  }
  return out;
}

// Label and value rows of the "network stack" part.
std::vector<std::pair<std::string, std::string>> StackRows(
    const WhoamiReport& report) {
  std::vector<std::pair<std::string, std::string>> rows = {
      {"HTTP", report.http_version.empty()
                   ? std::string("?")
                   : std::format("{}{}", report.http_version,
                                 report.offered_h2 ? " (offered h2)" : "")},
      {"JA4", report.ja4.empty() ? std::string("-") : report.ja4},
      {"TLS like", report.ja4.empty() ? std::string("-")
                                      : (report.tls_engines.empty()
                                             ? std::string("no known browser")
                                             : Joined(report.tls_engines))},
  };
  if (!report.h2_fingerprint.empty()) {
    rows.emplace_back("HTTP/2", report.h2_fingerprint);
  }
  if (!report.pseudo_order.empty()) {
    rows.emplace_back("Pseudo-headers", report.pseudo_order);
  }
  rows.emplace_back("Header order",
                    report.header_fp.empty() ? "-" : report.header_fp);
  rows.emplace_back("TCP TTL", TtlText(report.tcp_initial_ttl));
  rows.emplace_back("Round trips", RoundTripText(report));
  return rows;
}

std::string HtmlEscape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
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

std::string_view QueryValue(std::string_view query, std::string_view key) {
  while (!query.empty()) {
    const std::size_t amp = query.find('&');
    const std::string_view pair = query.substr(0, amp);
    const std::size_t eq = pair.find('=');
    if (pair.substr(0, eq) == key) {
      return eq == std::string_view::npos ? std::string_view()
                                          : pair.substr(eq + 1);
    }
    if (amp == std::string_view::npos) break;
    query.remove_prefix(amp + 1);
  }
  return {};
}

}  // namespace

std::vector<std::string> MatchingTlsEngines(const FingerprintLibrary& library,
                                            std::string_view ja4) {
  std::vector<std::string> engines;
  // t13d1516h2_8daaf6152771_02713d6af862: the middle part hashes the
  // cipher suites.
  const std::size_t first = ja4.find('_');
  if (first == std::string_view::npos) return engines;
  const std::string_view rest = ja4.substr(first + 1);
  const std::string_view ciphers = rest.substr(0, rest.find('_'));
  for (const std::string_view engine : {"chromium", "firefox", "webkit"}) {
    const BrowserProfile* profile = library.ProfileForEngine(engine);
    if (profile != nullptr &&
        std::ranges::find(profile->ja4_ciphers, ciphers) !=
            profile->ja4_ciphers.end()) {
      engines.emplace_back(engine);
    }
  }
  return engines;
}

std::string WhoamiHeadline(const WhoamiReport& report) {
  if (const std::string_view id = FindReason(report, "verified_crawler:");
      !id.empty()) {
    return std::format("a verified crawler ({})", id);
  }
  if (const std::string_view agent = FindReason(report, "verified_agent:");
      !agent.empty()) {
    return std::format("a verified signed agent ({})", agent);
  }
  if (const std::string_view id = FindReason(report, "known_automation:");
      !id.empty()) {
    return std::format("automation ({})", id);
  }
  if (!report.claimed_tool.empty()) {
    return std::format("{}, an HTTP tool or library", report.claimed_tool);
  }
  if (report.headless) return "a headless browser";
  if (!report.claimed_family.empty()) {
    if (report.bot_class == "human") {
      return std::format("a real browser ({})", Claimed(report));
    }
    return std::format(
        "something that claims to be {} but does not look "
        "like it",
        Claimed(report));
  }
  if (report.claims_crawler) return "a self-declared crawler, not verified";
  if (report.user_agent.empty()) return "an anonymous client (no User-Agent)";
  return "an unknown client";
}

namespace {

std::string Outcome(const WhoamiReport& report) {
  if (report.mode == "off") {
    return std::format(
        "{} is off: the gateway passes everything without a verdict.",
        report.host);
  }
  if (report.action == report.would_action) {
    return std::format("On {} ({}) you would be {}.", report.host, report.mode,
                       ActionPhrase(report.action));
  }
  return std::format("On {} ({}) you would be {} now; in enforce mode, {}.",
                     report.host, report.mode, ActionPhrase(report.action),
                     ActionPhrase(report.would_action));
}

}  // namespace

std::string RenderWhoamiText(const WhoamiReport& report) {
  std::string out = "LarpGuard: who am I\n\n";
  out += std::format("You look like {}.\n", WhoamiHeadline(report));
  if (report.mode != "off") {
    out += std::format("Verdict: {}, score {}{}.\n", report.bot_class,
                       report.score,
                       report.token_valid ? ", with a valid token" : "");
  }
  out += Outcome(report) + "\n\n";
  const auto row = [&out](std::string_view label, std::string_view value) {
    out += std::format("  {:<16}{}\n", label, value);
  };
  out += "Claims\n";
  row("User-Agent", report.user_agent.empty() ? "-" : report.user_agent);
  if (!report.claimed_tool.empty()) row("Tool", report.claimed_tool);
  if (const std::string claimed = Claimed(report); !claimed.empty()) {
    row("Browser", claimed);
  }
  out += "\nNetwork\n";
  row("Address", report.ip);
  row("Network", NetworkText(report));
  for (const auto& [label, value] : StackRows(report)) row(label, value);
  if (!report.reasons.empty()) {
    out += "\nReasons\n";
    for (const auto& [reason, weight] : report.reasons) {
      out += weight != 0 ? std::format("  {:>+4}  {}\n", weight, reason)
                         : std::format("        {}\n", reason);
    }
  }
  out += std::format("\nRequest {}\n", report.request_id);
  return out;
}

std::string RenderWhoamiJson(const WhoamiReport& report) {
  nlohmann::json reasons = nlohmann::json::array();
  for (const auto& [reason, weight] : report.reasons) {
    reasons.push_back({{"reason", reason}, {"weight", weight}});
  }
  const nlohmann::json json = {
      {"you_look_like", WhoamiHeadline(report)},
      {"outcome", Outcome(report)},
      {"request_id", report.request_id},
      {"host", report.host},
      {"mode", report.mode},
      {"verdict",
       {{"score", report.score},
        {"class", report.bot_class},
        {"reasons", reasons},
        {"token_valid", report.token_valid},
        {"action", report.action},
        {"would_action", report.would_action}}},
      {"claims",
       {{"user_agent", report.user_agent},
        {"family", report.claimed_family},
        {"major", report.claimed_major},
        {"os", report.claimed_os},
        {"tool", report.claimed_tool},
        {"crawler", report.claims_crawler},
        {"headless", report.headless}}},
      {"network",
       {{"ip", report.ip},
        {"ip_prefix", report.ip_prefix},
        {"asn", report.asn},
        {"asn_org", report.asn_org},
        {"hosting", report.hosting}}},
      {"stack",
       {{"http_version", report.http_version},
        {"offered_h2", report.offered_h2},
        {"ja4", report.ja4},
        {"tls_engines", report.tls_engines},
        {"h2_fingerprint", report.h2_fingerprint},
        {"pseudo_order", report.pseudo_order},
        {"header_fp", report.header_fp},
        {"tcp_initial_ttl", report.tcp_initial_ttl},
        {"tcp_rtt_us", report.tcp_rtt_us},
        {"handshake_us", report.handshake_us},
        {"relayed", LooksRelayed(report.tcp_rtt_us, report.handshake_us)}}},
  };
  return json.dump(2) + "\n";
}

std::string RenderWhoamiHtml(const WhoamiReport& report) {
  const std::string_view tone = report.bot_class == "bot"          ? "bad"
                                : report.bot_class == "suspicious" ? "warn"
                                                                   : "ok";
  std::string rows;
  const auto row = [&rows](std::string_view label, std::string_view value) {
    rows += std::format("<tr><th>{}</th><td>{}</td></tr>", HtmlEscape(label),
                        HtmlEscape(value));
  };
  row("User-Agent", report.user_agent.empty() ? "-" : report.user_agent);
  if (const std::string claimed = Claimed(report); !claimed.empty()) {
    row("Claims", claimed);
  }
  row("Address", report.ip);
  row("Network", NetworkText(report));
  for (const auto& [label, value] : StackRows(report)) row(label, value);
  std::string reasons;
  for (const auto& [reason, weight] : report.reasons) {
    reasons +=
        std::format("<li><span class=w>{}</span><code>{}</code></li>",
                    weight != 0 ? std::format("{:+}", weight) : std::string(),
                    HtmlEscape(reason));
  }
  if (reasons.empty()) reasons = "<li>No signals.</li>";
  return std::format(
      R"(<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Who am I · LarpGuard</title>
<style>
:root{{--bg:#0e0e0e;--fg:#ededed;--mute:#8c8c8c;--line:#262626;--card:#161616;
--ok:#3fb950;--warn:#d29922;--bad:#ff5e1f}}
@media (prefers-color-scheme:light){{:root{{--bg:#fafafa;--fg:#1f1f1f;
--mute:#6b6b6b;--line:#e5e5e5;--card:#fff}}}}
body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:40px 16px}}
h1{{font-size:28px;line-height:1.25;margin:4px 0 8px;font-weight:600}}
.eyebrow{{color:var(--mute);font-size:12px;letter-spacing:.08em;
text-transform:uppercase}}
.score{{display:inline-flex;gap:10px;align-items:baseline;margin:6px 0 4px}}
.score b{{font:600 34px/1 ui-monospace,monospace}}
.ok{{color:var(--ok)}}.warn{{color:var(--warn)}}.bad{{color:var(--bad)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;
margin-top:20px;overflow:hidden}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
th,td{{text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);
vertical-align:top}}
th{{color:var(--mute);font-weight:400;width:150px;white-space:nowrap}}
td{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}
ul{{list-style:none;margin:0;padding:6px 0}}
li{{padding:5px 14px;font-size:13.5px}}
.w{{display:inline-block;width:42px;color:var(--mute);
font-family:ui-monospace,monospace}}
code{{font-family:ui-monospace,monospace}}
p{{margin:4px 0;color:var(--mute)}}
</style></head><body><main>
<div class=eyebrow>LarpGuard · who am I</div>
<h1>You look like {}.</h1>
<div class=score><b class={}>{}</b><span class={}>{}</span>{}</div>
<p>{}</p>
<div class=card><table>{}</table></div>
<div class=card><ul>{}</ul></div>
<p style="margin-top:16px;font-size:12px">Request {}</p>
</main></body></html>
)",
      HtmlEscape(WhoamiHeadline(report)), tone, report.score, tone,
      HtmlEscape(report.mode == "off" ? "no verdict" : report.bot_class),
      report.token_valid ? "<span>· valid token</span>" : "",
      HtmlEscape(Outcome(report)), rows, reasons,
      HtmlEscape(report.request_id));
}

WhoamiFormat ChooseWhoamiFormat(std::string_view query,
                                std::string_view accept) {
  const std::string_view format = QueryValue(query, "format");
  if (format == "json") return WhoamiFormat::kJson;
  if (format == "text") return WhoamiFormat::kText;
  if (format == "html") return WhoamiFormat::kHtml;
  if (accept.find("application/json") != std::string_view::npos) {
    return WhoamiFormat::kJson;
  }
  if (accept.find("text/html") != std::string_view::npos) {
    return WhoamiFormat::kHtml;
  }
  return WhoamiFormat::kText;
}

}  // namespace bot_shield
