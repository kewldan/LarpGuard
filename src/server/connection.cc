#include "server/connection.h"

#include <openssl/ssl.h>

#include <array>
#include <asio/as_tuple.hpp>
#include <asio/connect.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl/host_name_verification.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <atomic>
#include <cstdint>
#include <format>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "common/log.h"
#include "common/metrics.h"
#include "net/prefixed_stream.h"
#include "net/proxy_protocol.h"
#include "net/socket_options.h"
#include "net/watchdog.h"
#include "tls/client_hello.h"

namespace bot_shield {
namespace {

using asio::ip::tcp;
using asio::experimental::awaitable_operators::operator&&;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kHelloReadChunk = 4096;
constexpr std::size_t kPumpBufferSize = 16 * 1024;

using ClientTlsStream = asio::ssl::stream<PrefixedStream<tcp::socket>>;
using UpstreamTlsStream = asio::ssl::stream<tcp::socket>;

struct ConnectionInfo {
  uint64_t id = 0;
  tcp::endpoint peer;
  tcp::endpoint local;
};

ConnectionInfo MakeConnectionInfo(const tcp::socket& socket) {
  static std::atomic<uint64_t> next_id{1};
  ConnectionInfo info;
  info.id = next_id.fetch_add(1, std::memory_order_relaxed);
  std::error_code ec;
  info.peer = socket.remote_endpoint(ec);
  info.local = socket.local_endpoint(ec);
  return info;
}

// Keeps the active-connections gauge in sync with handler lifetimes.
class ActiveConnection {
 public:
  ActiveConnection() { GlobalMetrics().connections_active.Add(1); }
  ~ActiveConnection() { GlobalMetrics().connections_active.Add(-1); }

  ActiveConnection(const ActiveConnection&) = delete;
  ActiveConnection& operator=(const ActiveConnection&) = delete;
};

template <typename Socket>
void CloseQuietly(Socket& socket) {
  std::error_code ec;
  socket.close(ec);
}

void ShutdownSend(tcp::socket& socket) {
  std::error_code ec;
  socket.shutdown(tcp::socket::shutdown_send, ec);
}

void SetNoDelay(tcp::socket& socket) {
  std::error_code ec;
  socket.set_option(tcp::no_delay(true), ec);
}

std::string SelectedAlpn(const SSL* ssl) {
  const uint8_t* data = nullptr;
  unsigned size = 0;
  SSL_get0_alpn_selected(ssl, &data, &size);
  return std::string(reinterpret_cast<const char*>(data), size);
}

std::vector<uint8_t> AlpnWireFormat(std::string_view protocol) {
  std::vector<uint8_t> wire;
  wire.reserve(protocol.size() + 1);
  wire.push_back(static_cast<uint8_t>(protocol.size()));
  wire.insert(wire.end(), protocol.begin(), protocol.end());
  return wire;
}

void CountRoute(const RouteDecision& decision) {
  Metrics& metrics = GlobalMetrics();
  switch (decision.reason) {
    case RouteReason::kCertificate:
      metrics.route_terminate.Inc();
      break;
    case RouteReason::kAcmeTlsAlpn:
      metrics.route_passthrough_acme_tls_alpn.Inc();
      break;
    case RouteReason::kNoServerName:
      metrics.route_passthrough_no_server_name.Inc();
      break;
    case RouteReason::kPassthroughPolicy:
      metrics.route_passthrough_policy.Inc();
      break;
    case RouteReason::kNoCertificate:
      metrics.route_passthrough_no_certificate.Inc();
      break;
    case RouteReason::kNotTls:
      if (decision.route == Route::kPassthrough) {
        metrics.route_passthrough_not_tls.Inc();
      } else {
        metrics.rejected_not_tls.Inc();
      }
      break;
    case RouteReason::kInvalidHello:
      metrics.rejected_invalid_hello.Inc();
      break;
  }
}

// Copies `from` -> `to` until EOF or error. Every read touches the idle
// watchdog. `on_eof` runs on a clean end of stream, `on_error` on failures.
template <typename From, typename To, typename OnEof, typename OnError>
asio::awaitable<void> Pump(From& from, To& to, Watchdog& watchdog,
                           Counter& bytes, OnEof on_eof, OnError on_error) {
  std::vector<uint8_t> buffer(kPumpBufferSize);
  while (true) {
    auto [read_ec, n] =
        co_await from.async_read_some(asio::buffer(buffer), kUse);
    if (n > 0) {
      watchdog.Touch();
      auto [write_ec, written] =
          co_await asio::async_write(to, asio::buffer(buffer.data(), n), kUse);
      if (write_ec) {
        on_error();
        co_return;
      }
      bytes.Inc(written);
    }
    if (read_ec) {
      if (read_ec == asio::error::eof) {
        on_eof();
      } else {
        on_error();
      }
      co_return;
    }
  }
}

// Bidirectional TCP relay with half-close support.
asio::awaitable<void> RelayTcp(tcp::socket& client, tcp::socket& upstream,
                               const Config& config) {
  auto executor = co_await asio::this_coro::executor;
  Metrics& metrics = GlobalMetrics();
  auto close_both = [&client, &upstream] {
    CloseQuietly(client);
    CloseQuietly(upstream);
  };
  ScopedWatchdog idle(executor, config.idle_timeout, [&metrics, close_both] {
    metrics.idle_timeouts.Inc();
    close_both();
  });
  co_await (Pump(
                client, upstream, *idle, metrics.bytes_client_to_upstream,
                [&upstream] { ShutdownSend(upstream); }, close_both) &&
            Pump(
                upstream, client, *idle, metrics.bytes_upstream_to_client,
                [&client] { ShutdownSend(client); }, close_both));
}

// Bidirectional relay between two TLS streams. TLS has no portable half-close
// in asio, so the first side to finish closes both.
asio::awaitable<void> RelayTls(ClientTlsStream& client,
                               UpstreamTlsStream& upstream,
                               const Config& config) {
  auto executor = co_await asio::this_coro::executor;
  Metrics& metrics = GlobalMetrics();
  auto close_both = [&client, &upstream] {
    CloseQuietly(client.lowest_layer());
    CloseQuietly(upstream.lowest_layer());
  };
  ScopedWatchdog idle(executor, config.idle_timeout, [&metrics, close_both] {
    metrics.idle_timeouts.Inc();
    close_both();
  });
  co_await (Pump(client, upstream, *idle, metrics.bytes_client_to_upstream,
                 close_both, close_both) &&
            Pump(upstream, client, *idle, metrics.bytes_upstream_to_client,
                 close_both, close_both));
}

// Connects to Traefik and sends the PROXY header if enabled.
asio::awaitable<std::optional<tcp::socket>> ConnectUpstream(
    const tcp::endpoint& endpoint, const ConnectionInfo& info,
    std::string_view authority, const Config& config) {
  auto executor = co_await asio::this_coro::executor;
  tcp::socket socket(executor);
  {
    ScopedWatchdog deadline(executor, config.upstream_connect_timeout,
                            [&socket] { CloseQuietly(socket); });
    auto [ec] = co_await socket.async_connect(endpoint, kUse);
    if (ec) {
      GlobalMetrics().upstream_connect_failures.Inc();
      log::Warn("conn={} upstream connect to {} failed: {}", info.id,
                FormatEndpoint(endpoint),
                deadline->expired() ? "timeout" : ec.message());
      co_return std::nullopt;
    }
  }
  SetNoDelay(socket);
  if (config.proxy_protocol) {
    const std::vector<uint8_t> header =
        EncodeProxyV2(info.peer, info.local, authority);
    auto [ec, n] =
        co_await asio::async_write(socket, asio::buffer(header), kUse);
    if (ec) {
      log::Warn("conn={} sending PROXY header failed: {}", info.id,
                ec.message());
      co_return std::nullopt;
    }
  }
  co_return std::optional<tcp::socket>(std::move(socket));
}

asio::awaitable<void> RunPassthrough(tcp::socket client,
                                     std::vector<uint8_t> prefix,
                                     const tcp::endpoint& upstream_endpoint,
                                     const ConnectionInfo& info,
                                     std::string_view authority,
                                     const GatewayContext& context) {
  std::optional<tcp::socket> upstream = co_await ConnectUpstream(
      upstream_endpoint, info, authority, *context.config);
  if (!upstream) co_return;
  if (!prefix.empty()) {
    auto [ec, n] =
        co_await asio::async_write(*upstream, asio::buffer(prefix), kUse);
    if (ec) co_return;
    GlobalMetrics().bytes_client_to_upstream.Inc(n);
  }
  co_await RelayTcp(client, *upstream, *context.config);
}

asio::awaitable<void> RunTerminate(tcp::socket socket,
                                   std::vector<uint8_t> prefix,
                                   std::shared_ptr<const CertEntry> certificate,
                                   std::string server_name,
                                   const ConnectionInfo& info,
                                   const GatewayContext& context) {
  const Config& config = *context.config;
  Metrics& metrics = GlobalMetrics();
  auto executor = co_await asio::this_coro::executor;

  ClientTlsStream client(
      PrefixedStream<tcp::socket>(std::move(socket), std::move(prefix)),
      *certificate->context);
  {
    ScopedWatchdog deadline(executor, config.tls_handshake_timeout,
                            [&client] { CloseQuietly(client.lowest_layer()); });
    auto [ec] =
        co_await client.async_handshake(asio::ssl::stream_base::server, kUse);
    if (ec) {
      metrics.tls_handshake_failures_client.Inc();
      log::Debug("conn={} client handshake failed: {}", info.id,
                 deadline->expired() ? "timeout" : ec.message());
      co_return;
    }
  }
  const std::string alpn = SelectedAlpn(client.native_handle());

  std::optional<tcp::socket> upstream_socket = co_await ConnectUpstream(
      context.upstream_https, info, server_name, config);
  if (!upstream_socket) co_return;

  UpstreamTlsStream upstream(std::move(*upstream_socket),
                             *context.upstream_tls);
  SSL_set_tlsext_host_name(upstream.native_handle(), server_name.c_str());
  if (!alpn.empty()) {
    // Offer only what the client negotiated so both legs speak the same
    // protocol and bytes can be relayed without re-framing.
    const std::vector<uint8_t> wire = AlpnWireFormat(alpn);
    SSL_set_alpn_protos(upstream.native_handle(), wire.data(), wire.size());
  }
  if (config.upstream_tls_verify) {
    upstream.set_verify_callback(
        asio::ssl::host_name_verification(server_name));
  }
  {
    ScopedWatchdog deadline(
        executor, config.tls_handshake_timeout,
        [&upstream] { CloseQuietly(upstream.lowest_layer()); });
    auto [ec] =
        co_await upstream.async_handshake(asio::ssl::stream_base::client, kUse);
    if (ec) {
      metrics.tls_handshake_failures_upstream.Inc();
      log::Warn("conn={} upstream handshake for {} failed: {}", info.id,
                server_name, deadline->expired() ? "timeout" : ec.message());
      co_return;
    }
  }
  const std::string upstream_alpn = SelectedAlpn(upstream.native_handle());
  // No ALPN on the upstream leg means HTTP/1.1, which is fine for a client
  // that negotiated http/1.1 explicitly.
  if (upstream_alpn != alpn && !(alpn == "http/1.1" && upstream_alpn.empty())) {
    metrics.alpn_mismatches.Inc();
    log::Warn("conn={} ALPN mismatch for {}: client={} upstream={}", info.id,
              server_name, alpn.empty() ? "-" : alpn,
              upstream_alpn.empty() ? "-" : upstream_alpn);
    co_return;
  }

  co_await RelayTls(client, upstream, config);
}

}  // namespace

std::string FormatEndpoint(const tcp::endpoint& endpoint) {
  if (endpoint.address().is_v6()) {
    return std::format("[{}]:{}", endpoint.address().to_string(),
                       endpoint.port());
  }
  return std::format("{}:{}", endpoint.address().to_string(), endpoint.port());
}

asio::awaitable<void> HandleHttpsConnection(tcp::socket socket,
                                            const GatewayContext& context) {
  ActiveConnection active;
  Metrics& metrics = GlobalMetrics();
  metrics.connections_https.Inc();
  const ConnectionInfo info = MakeConnectionInfo(socket);
  // The SYN is kept for fingerprinting (M1); for now only counted.
  if (!ReadSavedSyn(socket.native_handle()).empty()) {
    metrics.syn_captured.Inc();
  }
  SetNoDelay(socket);

  std::vector<uint8_t> buffer;
  buffer.reserve(kHelloReadChunk);
  ClientHello hello;
  ParseStatus status = ParseStatus::kNeedMore;
  {
    auto executor = co_await asio::this_coro::executor;
    ScopedWatchdog deadline(executor, context.config->client_hello_timeout,
                            [&socket] { CloseQuietly(socket); });
    std::array<uint8_t, kHelloReadChunk> chunk;
    while (status == ParseStatus::kNeedMore) {
      auto [ec, n] = co_await socket.async_read_some(asio::buffer(chunk), kUse);
      if (ec) {
        if (deadline->expired()) metrics.client_hello_timeouts.Inc();
        co_return;
      }
      buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
      status = ParseClientHello(buffer, &hello);
    }
  }

  RouteDecision decision = context.classifier->Classify(
      status, hello, *context.certificates->snapshot());
  CountRoute(decision);
  log::Debug("conn={} peer={} sni={} alpn={} route={} reason={}", info.id,
             FormatEndpoint(info.peer),
             hello.server_name.empty() ? "-" : hello.server_name,
             hello.alpn.empty() ? "-" : hello.alpn.front(),
             RouteName(decision.route), RouteReasonName(decision.reason));

  switch (decision.route) {
    case Route::kReject:
      co_return;
    case Route::kPassthrough:
      co_await RunPassthrough(std::move(socket), std::move(buffer),
                              context.upstream_https, info, hello.server_name,
                              context);
      co_return;
    case Route::kTerminate:
      co_await RunTerminate(std::move(socket), std::move(buffer),
                            std::move(decision.certificate),
                            std::move(hello.server_name), info, context);
      co_return;
  }
}

asio::awaitable<void> HandleHttpConnection(tcp::socket socket,
                                           const GatewayContext& context) {
  ActiveConnection active;
  GlobalMetrics().connections_http.Inc();
  const ConnectionInfo info = MakeConnectionInfo(socket);
  SetNoDelay(socket);
  co_await RunPassthrough(std::move(socket), {}, context.upstream_http, info,
                          "", context);
}

}  // namespace bot_shield
