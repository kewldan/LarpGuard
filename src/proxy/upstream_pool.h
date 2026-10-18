#ifndef BOT_SHIELD_PROXY_UPSTREAM_POOL_H_
#define BOT_SHIELD_PROXY_UPSTREAM_POOL_H_

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl/context.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "proxy/exchange.h"
#include "proxy/h2_upstream.h"
#include "proxy/transport.h"

namespace bot_shield {

struct UpstreamSettings {
  asio::ip::tcp::endpoint endpoint;
  // Client TLS context for Traefik (owned by the worker).
  asio::ssl::context* tls = nullptr;
  bool verify = false;
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds handshake_timeout{10000};
  std::chrono::milliseconds idle_timeout{90000};
  // HTTP/2 connections per SNI; requests beyond their stream limits queue.
  std::size_t max_connections_per_host = 4;
  // Streams per connection before another connection is opened.
  std::size_t streams_per_connection = 100;
};

using UpstreamTlsTransport =
    StreamTransport<asio::ssl::stream<asio::ip::tcp::socket>>;

// Per-worker pool of HTTP/2 connections to Traefik, keyed by the SNI the
// client used (Traefik picks certificates and TLS options by SNI). Not
// thread-safe: one pool per worker.
class UpstreamPool {
 public:
  UpstreamPool(asio::any_io_executor executor, UpstreamSettings settings);
  ~UpstreamPool();

  UpstreamPool(const UpstreamPool&) = delete;
  UpstreamPool& operator=(const UpstreamPool&) = delete;

  // Sends the exchange to Traefik; failures surface as FailUpstream().
  void Dispatch(const std::string& server_name,
                const std::shared_ptr<Exchange>& exchange);

  // A dedicated HTTP/1.1 TLS connection (WebSocket and other upgrades).
  asio::awaitable<std::unique_ptr<UpstreamTlsTransport>> ConnectHttp1(
      const std::string& server_name);

  // Closes idle connections now and the rest as their streams finish.
  void Drain();

 private:
  struct Slot {
    std::shared_ptr<H2UpstreamConnection> connection;
    std::vector<std::shared_ptr<Exchange>> pending;
    bool connecting = true;
  };

  asio::awaitable<void> Establish(std::shared_ptr<Slot> slot,
                                  std::string server_name);
  asio::awaitable<std::unique_ptr<UpstreamTlsTransport>> ConnectTls(
      const std::string& server_name, std::string_view alpn);
  asio::awaitable<void> DrainLoop();
  static std::size_t Load(const Slot& slot);

  asio::any_io_executor executor_;
  UpstreamSettings settings_;
  std::unordered_map<std::string, std::vector<std::shared_ptr<Slot>>> slots_;
  asio::steady_timer drain_timer_;
  bool draining_ = false;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_UPSTREAM_POOL_H_
