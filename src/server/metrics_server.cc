#include "server/metrics_server.h"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/read_until.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <format>
#include <string>
#include <string_view>

#include "common/log.h"
#include "common/metrics.h"
#include "net/watchdog.h"

namespace bot_shield {
namespace {

using asio::ip::tcp;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kMaxRequestSize = 8192;
constexpr auto kRequestTimeout = std::chrono::seconds(5);

std::string Response(std::string_view status, std::string_view content_type,
                     std::string_view body) {
  return std::format(
      "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n"
      "Connection: close\r\n\r\n{}",
      status, content_type, body.size(), body);
}

asio::awaitable<void> HandleRequest(tcp::socket socket) {
  auto executor = co_await asio::this_coro::executor;
  ScopedWatchdog deadline(executor, kRequestTimeout, [&socket] {
    std::error_code ec;
    socket.close(ec);
  });

  std::string request;
  auto [read_ec, n] = co_await asio::async_read_until(
      socket, asio::dynamic_buffer(request, kMaxRequestSize), "\r\n\r\n", kUse);
  if (read_ec) co_return;

  const std::string_view line =
      std::string_view(request).substr(0, request.find("\r\n"));
  std::string response;
  if (line.starts_with("GET /metrics ")) {
    response = Response("200 OK", "text/plain; version=0.0.4",
                        GlobalMetrics().RenderPrometheus());
  } else if (line.starts_with("GET /health ")) {
    response = Response("200 OK", "text/plain", "ok\n");
  } else {
    response = Response("404 Not Found", "text/plain", "not found\n");
  }
  co_await asio::async_write(socket, asio::buffer(response), kUse);
}

}  // namespace

asio::awaitable<void> ServeMetrics(tcp::acceptor& acceptor) {
  auto executor = co_await asio::this_coro::executor;
  while (true) {
    auto [ec, socket] = co_await acceptor.async_accept(kUse);
    if (ec) {
      if (!acceptor.is_open()) co_return;
      log::Warn("metrics: accept failed: {}", ec.message());
      continue;
    }
    asio::co_spawn(executor, HandleRequest(std::move(socket)), asio::detached);
  }
}

}  // namespace bot_shield
