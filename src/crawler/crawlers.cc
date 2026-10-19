#include "crawler/crawlers.h"

#include <array>
#include <cctype>
#include <span>
#include <string>
#include <string_view>

namespace bot_shield {
namespace {

using Names = std::span<const std::string_view>;

// Search engines publish the reverse DNS domains of their crawlers; a claim
// is verified by reverse lookup plus a forward lookup back to the address.
constexpr std::array<std::string_view, 7> kGoogleTokens = {
    "googlebot",         "googleother",          "google-inspectiontool",
    "adsbot-google",     "mediapartners-google", "storebot-google",
    "feedfetcher-google"};
constexpr std::array<std::string_view, 3> kGoogleDomains = {
    "googlebot.com", "google.com", "googleusercontent.com"};
constexpr std::array<std::string_view, 4> kBingTokens = {
    "bingbot", "adidxbot", "bingpreview", "msnbot"};
constexpr std::array<std::string_view, 1> kBingDomains = {"search.msn.com"};
constexpr std::array<std::string_view, 1> kYandexTokens = {"yandex"};
constexpr std::array<std::string_view, 3> kYandexDomains = {
    "yandex.ru", "yandex.net", "yandex.com"};
constexpr std::array<std::string_view, 1> kAppleTokens = {"applebot"};
constexpr std::array<std::string_view, 1> kAppleDomains = {
    "applebot.apple.com"};
constexpr std::array<std::string_view, 1> kBaiduTokens = {"baiduspider"};
constexpr std::array<std::string_view, 2> kBaiduDomains = {"baidu.com",
                                                           "baidu.jp"};
constexpr std::array<std::string_view, 1> kPetalTokens = {"petalbot"};
constexpr std::array<std::string_view, 1> kPetalDomains = {"petalsearch.com"};
constexpr std::array<std::string_view, 1> kSeznamTokens = {"seznambot"};
constexpr std::array<std::string_view, 1> kSeznamDomains = {"seznam.cz"};
constexpr std::array<std::string_view, 1> kNaverTokens = {"yeti/"};
constexpr std::array<std::string_view, 1> kNaverDomains = {"naver.com"};
constexpr std::array<std::string_view, 1> kAmazonTokens = {"amazonbot"};
constexpr std::array<std::string_view, 1> kAmazonDomains = {
    "crawl.amazonbot.amazon"};

constexpr std::array<std::string_view, 2> kDuckDuckGoTokens = {"duckduckbot",
                                                               "duckassistbot"};
constexpr std::array<std::string_view, 1> kMistralTokens = {"mistralai-user"};

// Published IP ranges (checked live; Google's format).
constexpr std::array<std::string_view, 4> kGoogleRanges = {
    "https://developers.google.com/static/search/apis/ipranges/"
    "googlebot.json",
    "https://developers.google.com/static/search/apis/ipranges/"
    "special-crawlers.json",
    "https://developers.google.com/static/search/apis/ipranges/"
    "user-triggered-fetchers.json",
    "https://developers.google.com/static/search/apis/ipranges/"
    "user-triggered-fetchers-google.json"};
constexpr std::array<std::string_view, 1> kBingRanges = {
    "https://www.bing.com/toolbox/bingbot.json"};
constexpr std::array<std::string_view, 1> kAppleRanges = {
    "https://search.developer.apple.com/applebot.json"};
constexpr std::array<std::string_view, 1> kDuckDuckGoRanges = {
    "https://duckduckgo.com/duckduckbot.json"};
constexpr std::array<std::string_view, 3> kOpenAiRanges = {
    "https://openai.com/gptbot.json", "https://openai.com/searchbot.json",
    "https://openai.com/chatgpt-user.json"};
constexpr std::array<std::string_view, 2> kPerplexityRanges = {
    "https://www.perplexity.com/perplexitybot.json",
    "https://www.perplexity.com/perplexity-user.json"};
constexpr std::array<std::string_view, 1> kMistralRanges = {
    "https://mistral.ai/mistralai-user-ips.json"};

// AI crawlers and assistants, by User-Agent only.
constexpr std::array<std::string_view, 3> kOpenAiTokens = {
    "gptbot", "chatgpt-user", "oai-searchbot"};
constexpr std::array<std::string_view, 4> kAnthropicTokens = {
    "claudebot", "claude-user", "claude-searchbot", "anthropic-ai"};
constexpr std::array<std::string_view, 1> kCommonCrawlTokens = {"ccbot"};
constexpr std::array<std::string_view, 2> kPerplexityTokens = {
    "perplexitybot", "perplexity-user"};
constexpr std::array<std::string_view, 1> kByteDanceTokens = {"bytespider"};
constexpr std::array<std::string_view, 2> kCohereTokens = {
    "cohere-ai", "cohere-training-data-crawler"};
constexpr std::array<std::string_view, 3> kMetaTokens = {
    "meta-externalagent", "meta-externalfetcher", "facebookbot"};
constexpr std::array<std::string_view, 1> kDiffbotTokens = {"diffbot"};
constexpr std::array<std::string_view, 1> kYouTokens = {"youbot"};
constexpr std::array<std::string_view, 1> kTimpiTokens = {"timpibot"};
constexpr std::array<std::string_view, 1> kImagesiftTokens = {"imagesiftbot"};
constexpr std::array<std::string_view, 1> kOmgiliTokens = {"omgili"};

constexpr Names kNone;

constexpr std::array<KnownCrawler, 23> kCrawlers = {{
    {"google", kGoogleTokens, kGoogleDomains, false, kGoogleRanges},
    {"bing", kBingTokens, kBingDomains, false, kBingRanges},
    {"yandex", kYandexTokens, kYandexDomains, false, kNone},
    {"apple", kAppleTokens, kAppleDomains, false, kAppleRanges},
    {"duckduckgo", kDuckDuckGoTokens, kNone, false, kDuckDuckGoRanges},
    {"baidu", kBaiduTokens, kBaiduDomains, false, kNone},
    {"petal", kPetalTokens, kPetalDomains, false, kNone},
    {"seznam", kSeznamTokens, kSeznamDomains, false, kNone},
    {"naver", kNaverTokens, kNaverDomains, false, kNone},
    {"amazon", kAmazonTokens, kAmazonDomains, true, kNone},
    {"openai", kOpenAiTokens, kNone, true, kOpenAiRanges},
    {"anthropic", kAnthropicTokens, kNone, true, kNone},
    {"commoncrawl", kCommonCrawlTokens, kNone, true, kNone},
    {"perplexity", kPerplexityTokens, kNone, true, kPerplexityRanges},
    {"mistral", kMistralTokens, kNone, true, kMistralRanges},
    {"bytedance", kByteDanceTokens, kNone, true, kNone},
    {"cohere", kCohereTokens, kNone, true, kNone},
    {"meta", kMetaTokens, kNone, true, kNone},
    {"diffbot", kDiffbotTokens, kNone, true, kNone},
    {"you", kYouTokens, kNone, true, kNone},
    {"timpi", kTimpiTokens, kNone, true, kNone},
    {"imagesift", kImagesiftTokens, kNone, true, kNone},
    {"omgili", kOmgiliTokens, kNone, true, kNone},
}};

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

}  // namespace

std::span<const KnownCrawler> KnownCrawlers() { return kCrawlers; }

const KnownCrawler* FindCrawler(std::string_view user_agent) {
  if (user_agent.empty()) return nullptr;
  const std::string lower = Lowercase(user_agent);
  for (const KnownCrawler& crawler : kCrawlers) {
    for (const std::string_view token : crawler.tokens) {
      if (lower.find(token) != std::string::npos) return &crawler;
    }
  }
  return nullptr;
}

bool HostnameInDomains(std::string_view hostname,
                       std::span<const std::string_view> domains) {
  std::string name = Lowercase(hostname);
  if (name.ends_with('.')) name.pop_back();
  for (const std::string_view domain : domains) {
    if (name == domain) return true;
    if (name.size() > domain.size() && name.ends_with(domain) &&
        name[name.size() - domain.size() - 1] == '.') {
      return true;
    }
  }
  return false;
}

}  // namespace bot_shield
