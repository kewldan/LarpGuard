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

}  // namespace

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
