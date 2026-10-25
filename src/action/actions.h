#ifndef BOT_SHIELD_ACTION_ACTIONS_H_
#define BOT_SHIELD_ACTION_ACTIONS_H_

#include <asio/any_io_executor.hpp>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include "proxy/exchange.h"

namespace bot_shield {

struct TarpitSettings {
  std::chrono::milliseconds duration{30000};
  std::chrono::milliseconds interval{1000};
  std::size_t chunk = 16;
  std::size_t max_active = 1000;
};

// Answers `exchange` with 200 and a body that trickles out `chunk` bytes
// every `interval` until `duration` (docs/architecture.md, 6.2): a scraper
// waits instead of retrying elsewhere. Returns false (nothing started) when
// `max_active` tarpits are already running; the caller blocks instead.
bool StartTarpit(const asio::any_io_executor& executor,
                 const std::shared_ptr<Exchange>& exchange,
                 const TarpitSettings& settings);

// Watermark of one decoy answer: a short token derived from the request id
// with a secret, so leaked decoy data can be traced to the request (and
// its event) without storing anything.
std::string DecoyWatermark(std::string_view secret,
                           std::string_view request_id);

// A decoy body: `custom` (or the built-in page for `html`/JSON) with every
// "{{watermark}}" replaced.
std::string RenderDecoy(std::string_view custom, bool html,
                        std::string_view watermark);

// An endless maze for crawlers that ignore robots.txt (decoy.labyrinth):
// a page of plausible filler text whose links lead to more such pages on
// the same host. The page for a path is always the same (derived from
// `secret`), so the maze looks like a real site; it carries the watermark
// and asks search engines not to index or follow it.
std::string RenderLabyrinth(std::string_view secret, std::string_view path,
                            std::string_view watermark);

// robots.txt for AI crawlers under crawlers.ai_robots: everything is off
// limits.
inline constexpr std::string_view kAiRobotsTxt =
    "# AI crawlers are not welcome on this site.\n"
    "User-agent: *\n"
    "Disallow: /\n";

}  // namespace bot_shield

#endif  // BOT_SHIELD_ACTION_ACTIONS_H_
