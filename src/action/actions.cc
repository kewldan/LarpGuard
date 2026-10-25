#include "action/actions.h"

#include <algorithm>
#include <asio/any_io_executor.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "common/hash.h"
#include "common/metrics.h"
#include "proxy/exchange.h"

namespace bot_shield {
namespace {

constexpr std::string_view kDecoyHtml = R"html(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Catalog</title>
<meta name="robots" content="noindex"></head><body>
<h1>Catalog</h1>
<ul class="products">
<li data-sku="{{watermark}}-01"><span class="name">Basic plan</span> <span class="price">19.90</span></li>
<li data-sku="{{watermark}}-02"><span class="name">Pro plan</span> <span class="price">49.00</span></li>
<li data-sku="{{watermark}}-03"><span class="name">Team plan</span> <span class="price">129.00</span></li>
</ul>
<p class="contact">sales-{{watermark}}@example.com</p>
</body></html>
)html";

constexpr std::string_view kDecoyJson =
    R"json({"items":[{"id":"{{watermark}}-01","name":"Basic plan","price":19.9},)json"
    R"json({"id":"{{watermark}}-02","name":"Pro plan","price":49.0}],"total":2})json"
    "\n";

// Releases the slot StartTarpit took in tarpits_active (all workers).
struct TarpitSlot {
  TarpitSlot() = default;
  TarpitSlot(const TarpitSlot&) = delete;
  TarpitSlot& operator=(const TarpitSlot&) = delete;
  ~TarpitSlot() { GlobalMetrics().tarpits_active.Add(-1); }
};

asio::awaitable<void> Trickle(std::weak_ptr<Exchange> weak, int64_t chunks,
                              std::size_t chunk_size,
                              std::chrono::milliseconds interval) {
  const TarpitSlot slot;
  asio::steady_timer timer(co_await asio::this_coro::executor);
  const std::string filler(chunk_size, ' ');
  for (int64_t i = 0; i < chunks; ++i) {
    timer.expires_after(interval);
    co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
    const std::shared_ptr<Exchange> exchange = weak.lock();
    if (exchange == nullptr || exchange->client_cancelled) co_return;
    exchange->PushLocalBody(filler);
  }
  if (const std::shared_ptr<Exchange> exchange = weak.lock()) {
    exchange->EndLocalBody();
  }
}

constexpr std::string_view kWords[] = {
    "archive",   "annual",    "analysis",  "board",     "budget",  "catalog",
    "center",    "change",    "community", "council",   "data",    "design",
    "digital",   "district",  "energy",    "estate",    "field",   "finance",
    "forum",     "general",   "global",    "group",     "guide",   "history",
    "housing",   "industry",  "institute", "journal",   "library", "local",
    "market",    "material",  "media",     "member",    "method",  "network",
    "notes",     "office",    "open",      "planning",  "policy",  "practice",
    "program",   "project",   "public",    "quarterly", "record",  "regional",
    "report",    "research",  "review",    "school",    "science", "service",
    "society",   "standard",  "studies",   "summary",   "survey",  "system",
    "technical", "transport", "update",    "water"};

// Deterministic pseudo-random words: bytes of an HMAC chain.
class WordStream {
 public:
  WordStream(std::string_view secret, std::string_view seed)
      : secret_(secret), seed_(seed) {}

  std::string_view Next() {
    return kWords[static_cast<std::size_t>(Byte()) % std::size(kWords)];
  }

  int Below(int limit) { return Byte() % limit; }

  // No word twice in a row: "office office" gives the filler away.
  std::string Words(int count) {
    std::string out;
    std::string_view last;
    for (int i = 0; i < count; ++i) {
      std::string_view word = Next();
      while (word == last) word = Next();
      if (i > 0) out.push_back(' ');
      out += word;
      last = word;
    }
    return out;
  }

 private:
  int Byte() {
    if (offset_ + 2 > block_.size()) {
      block_ =
          HmacSha256Hex(secret_, std::format("{}#{}", seed_, counter_++), 64);
      offset_ = 0;
    }
    const int value = std::stoi(block_.substr(offset_, 2), nullptr, 16);
    offset_ += 2;
    return value;
  }

  std::string_view secret_;
  std::string seed_;
  std::string block_;
  std::size_t offset_ = 0;
  int counter_ = 0;
};

std::string Capitalized(std::string text) {
  if (!text.empty() && text[0] >= 'a' && text[0] <= 'z') {
    text[0] = static_cast<char>(text[0] - 'a' + 'A');
  }
  return text;
}

}  // namespace

std::string RenderLabyrinth(std::string_view secret, std::string_view path,
                            std::string_view watermark) {
  WordStream words(secret, path);
  const std::string title = Capitalized(words.Words(3));
  std::string out = std::format(
      "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
      "<title>{}</title>\n<meta name=\"robots\" content=\"noindex,nofollow\">"
      "</head><body data-ref=\"{}\">\n<h1>{}</h1>\n",
      title, watermark, title);
  for (int paragraph = 0; paragraph < 4; ++paragraph) {
    out += "<p>" + Capitalized(words.Words(28 + words.Below(16))) + ".</p>\n";
  }
  out += "<ul>\n";
  for (int link = 0; link < 12; ++link) {
    const std::string target = std::format(
        "/{}/{}", words.Next(),
        HmacSha256Hex(secret, std::format("{}>{}", path, link), 10));
    out += std::format("<li><a rel=\"nofollow\" href=\"{}\">{}</a></li>\n",
                       target, Capitalized(words.Words(2 + words.Below(3))));
  }
  out += std::format("</ul>\n<p class=\"ref\">Ref. {}</p>\n</body></html>\n",
                     watermark);
  return out;
}

bool StartTarpit(const asio::any_io_executor& executor,
                 const std::shared_ptr<Exchange>& exchange,
                 const TarpitSettings& settings) {
  Gauge& active = GlobalMetrics().tarpits_active;
  if (std::cmp_greater_equal(active.Get(), settings.max_active)) return false;
  active.Add(1);
  const int64_t chunks = std::max<int64_t>(
      1, settings.duration.count() / settings.interval.count());
  exchange->StartLocalStream(
      200, static_cast<std::size_t>(chunks) * settings.chunk,
      {{"cache-control", "no-store"}}, "text/html; charset=utf-8");
  asio::co_spawn(executor,
                 Trickle(exchange, chunks, settings.chunk, settings.interval),
                 asio::detached);
  return true;
}

std::string DecoyWatermark(std::string_view secret,
                           std::string_view request_id) {
  return HmacSha256Hex(secret, request_id, 12);
}

std::string RenderDecoy(std::string_view custom, bool html,
                        std::string_view watermark) {
  std::string out(!custom.empty() ? custom : html ? kDecoyHtml : kDecoyJson);
  constexpr std::string_view kPlaceholder = "{{watermark}}";
  for (std::size_t at = out.find(kPlaceholder); at != std::string::npos;
       at = out.find(kPlaceholder, at + watermark.size())) {
    out.replace(at, kPlaceholder.size(), watermark);
  }
  return out;
}

}  // namespace bot_shield
