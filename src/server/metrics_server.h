#ifndef BOT_SHIELD_SERVER_METRICS_SERVER_H_
#define BOT_SHIELD_SERVER_METRICS_SERVER_H_

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>

#include "server/health.h"

namespace bot_shield {

// Minimal HTTP/1.1 server for GET /metrics (Prometheus) and GET /health
// (503 when a worker loop is stalled; the fail-open watchdog polls it).
// Meant for loopback only; one request per connection.
asio::awaitable<void> ServeMetrics(asio::ip::tcp::acceptor& acceptor,
                                   const Heartbeats* heartbeats);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_METRICS_SERVER_H_
