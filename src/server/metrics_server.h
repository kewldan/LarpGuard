#ifndef BOT_SHIELD_SERVER_METRICS_SERVER_H_
#define BOT_SHIELD_SERVER_METRICS_SERVER_H_

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>

namespace bot_shield {

// Minimal HTTP/1.1 server for GET /metrics (Prometheus) and GET /health.
// Meant for loopback only; one request per connection.
asio::awaitable<void> ServeMetrics(asio::ip::tcp::acceptor& acceptor);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_METRICS_SERVER_H_
