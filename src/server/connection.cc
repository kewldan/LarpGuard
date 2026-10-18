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
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/log.h"
#include "common/metrics.h"
#include "config/config.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "fp/h1_tap.h"
#include "fp/http_request.h"
#include "fp/ja4.h"
#include "fp/tcp_syn.h"
#include "net/classifier.h"
#include "net/prefixed_stream.h"
#include "net/proxy_protocol.h"
#include "net/socket_options.h"
#include "net/watchdog.h"
#include "proxy/exchange.h"
#include "proxy/h1_server.h"
#include "proxy/h2_server.h"
#include "proxy/http_message.h"
#include "proxy/proxy_hooks.h"
#include "proxy/transport.h"
#include "tls/cert_store.h"
#include "tls/client_hello.h"

#if BOT_SHIELD_FOXIO
#include "fp/foxio/ja4plus.h"
#endif

namespace bot_shield {
namespace {

using asio::ip::tcp;
// Used by `co_await (a && b)`; clang-tidy does not see operator lookups.
// NOLINTNEXTLINE(misc-unused-using-decls)
using asio::experimental::awaitable_operators::operator&&;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kHelloReadChunk = 4096;
constexpr std::size_t kPumpBufferSize = std::size_t{16} * 1024;

using ClientTlsStream = asio::ssl::stream<PrefixedStream<tcp::socket>>;

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

// Per-connection observation: fingerprints, byte counters and the passive HTTP
// taps. Emits a "conn" event when the handler finishes and a "req" event for
// every request the taps see. Never touches the proxied bytes.
class ConnectionObserver {
 public:
  ConnectionObserver(const GatewayContext& context, const ConnectionInfo& info,
                     std::string listener)
      : context_(context) {
    record_.id = info.id;
    record_.started_ms = UnixMillis();
    record_.listener = std::move(listener);
    record_.peer = info.peer.address();
  }

  ~ConnectionObserver() {
    if (context_.events == nullptr) return;
    try {
      context_.events->Publish(
          "conn",
          ConnectionEventJson(record_, *context_.event_settings, UnixMillis()));
    } catch (...) {
      // Destructors must not throw; logging could throw again.
      GlobalMetrics().events_dropped.Inc();
    }
  }

  ConnectionObserver(const ConnectionObserver&) = delete;
  ConnectionObserver& operator=(const ConnectionObserver&) = delete;

  ConnectionRecord& record() { return record_; }

  void OnSyn(std::span<const uint8_t> packet) {
    TcpSyn syn;
    if (!ParseTcpSyn(packet, &syn)) return;
    record_.tcp_fingerprint = TcpFingerprint(syn);
#if BOT_SHIELD_FOXIO
    record_.ja4t = foxio::Ja4t(syn);
#endif
  }

  void OnClientHello(const ClientHello& hello) {
    record_.server_name = hello.server_name;
    record_.tls_version = TlsVersionCode(hello);
    if (!hello.alpn.empty()) record_.alpn_offered = hello.alpn.front();
    record_.ja4 = Ja4(hello);
    record_.ja4_raw = Ja4Raw(hello);
  }

  void OnRoute(std::string_view route, std::string_view reason) {
    record_.route = route;
    record_.reason = reason;
  }

  // Starts reading the plaintext HTTP/1.x a client sends on port 80. Only
  // with events on: nothing else consumes what the tap produces. Terminated
  // TLS traffic goes through the proxy instead.
  void StartHttpTap() {
    if (context_.events == nullptr || !context_.event_settings->requests) {
      return;
    }
    h1_ = std::make_unique<H1Tap>(
        [this](HttpRequest&& request) { OnRequest(std::move(request)); });
  }

  void OnClientData(std::span<const uint8_t> data) {
    record_.bytes_in += data.size();
    GlobalMetrics().bytes_client_to_upstream.Inc(data.size());
    if (h1_ && h1_->active()) h1_->Feed(data);
  }

  void OnUpstreamData(std::span<const uint8_t> data) {
    OnBytesToClient(data.size());
  }

  void OnBytesToClient(std::size_t size) {
    record_.bytes_out += size;
    GlobalMetrics().bytes_upstream_to_client.Inc(size);
  }

  // Request headers parsed by the proxy; the place for verdicts (M2 scoring).
  void OnProxyRequest(Exchange& /*exchange*/) {}

  void OnProxyDone(const Exchange& exchange) {
    ++record_.requests;
    GlobalMetrics().http_requests_observed.Inc();
    if (!exchange.h2_fingerprint.empty()) {
      record_.h2_fingerprint = exchange.h2_fingerprint;
    }
    if (context_.events == nullptr || !context_.event_settings->requests) {
      return;
    }
    RequestOutcome outcome;
    outcome.status = exchange.response_started ? exchange.response.status : 0;
    outcome.duration_ms = SteadyMillis() - exchange.started_ms;
    outcome.response_bytes = exchange.response_bytes;
    outcome.local = exchange.local;
    try {
      context_.events->Publish(
          "req",
          RequestEventJson(record_, exchange.observed, record_.requests,
                           *context_.event_settings, UnixMillis(), &outcome));
    } catch (const std::exception& e) {
      log::Warn("conn={} request event dropped: {}", record_.id, e.what());
    }
  }

 private:
  void OnRequest(HttpRequest&& request) {
    ++record_.requests;
    GlobalMetrics().http_requests_observed.Inc();
    try {
      context_.events->Publish(
          "req", RequestEventJson(record_, request, record_.requests,
                                  *context_.event_settings, UnixMillis()));
    } catch (const std::exception& e) {
      log::Warn("conn={} request event dropped: {}", record_.id, e.what());
    }
  }

  const GatewayContext& context_;
  ConnectionRecord record_;
  std::unique_ptr<H1Tap> h1_;
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
  return {reinterpret_cast<const char*>(data), size};
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
// watchdog; `on_data` sees each chunk after it was forwarded. `on_eof` runs
// on a clean end of stream, `on_error` on failures.
template <typename From, typename To, typename OnData, typename OnEof,
          typename OnError>
asio::awaitable<void> Pump(From& from, To& to, Watchdog& watchdog,
                           OnData on_data, OnEof on_eof, OnError on_error) {
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
      on_data(std::span<const uint8_t>(buffer.data(), written));
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
                               const Config& config,
                               ConnectionObserver& observer) {
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
  auto on_client_data = [&observer](std::span<const uint8_t> data) {
    observer.OnClientData(data);
  };
  auto on_upstream_data = [&observer](std::span<const uint8_t> data) {
    observer.OnUpstreamData(data);
  };
  co_await (Pump(
                client, upstream, *idle, on_client_data,
                [&upstream] { ShutdownSend(upstream); }, close_both) &&
            Pump(
                upstream, client, *idle, on_upstream_data,
                [&client] { ShutdownSend(client); }, close_both));
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
                                     const GatewayContext& context,
                                     ConnectionObserver& observer) {
  std::optional<tcp::socket> upstream = co_await ConnectUpstream(
      upstream_endpoint, info, authority, *context.config);
  if (!upstream) co_return;
  if (!prefix.empty()) {
    auto [ec, n] =
        co_await asio::async_write(*upstream, asio::buffer(prefix), kUse);
    if (ec) co_return;
    observer.OnClientData(std::span<const uint8_t>(prefix.data(), n));
  }
  co_await RelayTcp(client, *upstream, *context.config, observer);
}

asio::awaitable<void> RunTerminate(tcp::socket socket,
                                   std::vector<uint8_t> prefix,
                                   std::shared_ptr<const CertEntry> certificate,
                                   std::string server_name,
                                   const ConnectionInfo& info,
                                   const GatewayContext& context,
                                   ConnectionObserver& observer) {
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
  observer.record().alpn = alpn;

  ClientInfo client_info;
  client_info.address = info.peer.address();
  client_info.local_port = info.local.port();
  client_info.server_name = std::move(server_name);
  ProxyHooks hooks;
  hooks.on_request = [&observer](Exchange& exchange) {
    observer.OnProxyRequest(exchange);
  };
  hooks.on_done = [&observer](const Exchange& exchange) {
    observer.OnProxyDone(exchange);
  };
  hooks.on_client_bytes = [&observer](std::span<const uint8_t> data) {
    observer.OnClientData(data);
  };
  hooks.on_bytes_to_client = [&observer](std::size_t size) {
    observer.OnBytesToClient(size);
  };

  auto transport =
      std::make_unique<StreamTransport<ClientTlsStream>>(std::move(client));
  if (alpn == "h2") {
    auto server = H2ServerConnection::Create(
        std::move(transport), context.pool, std::move(client_info),
        std::move(hooks), context.proxy_settings);
    server->Start();
    co_await server->WaitClosed();
    server->DetachHooks();
  } else {
    auto server = H1ServerConnection::Create(
        std::move(transport), context.pool, std::move(client_info),
        std::move(hooks), context.proxy_settings);
    co_await server->Run();
    server->DetachHooks();
  }
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
  ConnectionObserver observer(context, info, "https");
  if (const auto syn = ReadSavedSyn(socket.native_handle()); !syn.empty()) {
    metrics.syn_captured.Inc();
    observer.OnSyn(syn);
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
        observer.OnRoute("reject", deadline->expired() ? "client_hello_timeout"
                                                       : "closed_before_hello");
        co_return;
      }
      buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
      status = ParseClientHello(buffer, &hello);
    }
  }

  RouteDecision decision = context.classifier->Classify(
      status, hello, *context.certificates->snapshot());
  CountRoute(decision);
  if (status == ParseStatus::kOk) observer.OnClientHello(hello);
  observer.OnRoute(RouteName(decision.route), RouteReasonName(decision.reason));
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
                              context, observer);
      co_return;
    case Route::kTerminate:
      co_await RunTerminate(
          std::move(socket), std::move(buffer), std::move(decision.certificate),
          std::move(hello.server_name), info, context, observer);
      co_return;
  }
}

asio::awaitable<void> HandleHttpConnection(tcp::socket socket,
                                           const GatewayContext& context) {
  ActiveConnection active;
  Metrics& metrics = GlobalMetrics();
  metrics.connections_http.Inc();
  const ConnectionInfo info = MakeConnectionInfo(socket);
  ConnectionObserver observer(context, info, "http");
  if (const auto syn = ReadSavedSyn(socket.native_handle()); !syn.empty()) {
    metrics.syn_captured.Inc();
    observer.OnSyn(syn);
  }
  observer.OnRoute("passthrough", "plain_http");
  // Plain HTTP is readable as is: tap it like a terminated HTTP/1.1 stream.
  observer.StartHttpTap();
  SetNoDelay(socket);
  co_await RunPassthrough(std::move(socket), {}, context.upstream_http, info,
                          "", context, observer);
}

}  // namespace bot_shield
