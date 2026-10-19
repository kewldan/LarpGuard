#ifndef BOT_SHIELD_CRAWLER_CRAWLERS_H_
#define BOT_SHIELD_CRAWLER_CRAWLERS_H_

#include <span>
#include <string_view>

namespace bot_shield {

enum class CrawlerStatus { kPending, kVerified, kFailed };

// A crawler the gateway knows by name (docs/architecture.md, section 5.5).
struct KnownCrawler {
  std::string_view id;
  // Lowercase User-Agent substrings that claim this crawler.
  std::span<const std::string_view> tokens;
  // Reverse DNS suffixes of its real addresses; empty: cannot be verified.
  std::span<const std::string_view> domains;
  // Collects data for AI models or answers AI assistants (crawlers.ai).
  bool ai = false;
  // Published IP range lists (JSON, see ParseCrawlerRanges). With ranges
  // but no domains, an address outside them is a fake.
  std::span<const std::string_view> ranges;
};

std::span<const KnownCrawler> KnownCrawlers();

// The crawler a User-Agent claims to be, or null.
const KnownCrawler* FindCrawler(std::string_view user_agent);

// `hostname` (any case, optional trailing dot) is one of `domains` or a
// subdomain of one.
bool HostnameInDomains(std::string_view hostname,
                       std::span<const std::string_view> domains);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CRAWLER_CRAWLERS_H_
