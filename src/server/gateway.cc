#include "server/gateway.h"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "common/log.h"
#include "common/metrics.h"
#include "config/config.h"
#include "docker/labels.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "fp/library.h"
#include "net/socket_options.h"
#include "proxy/upstream_pool.h"
#include "ratelimit/gcra.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/rules.h"
#include "server/connection.h"
#include "server/metrics_server.h"
#include "tls/cert_store.h"

namespace bot_shield {
namespace {

using asio::ip::tcp;

constexpr int kListenBacklog = 4096;

void LogUnhandled(const std::exception_ptr& error) {
  if (!error) return;
  try {
    std::rethrow_exception(error);
  } catch (const std::exception& e) {
    log::Error("unhandled exception in connection: {}", e.what());
  } catch (...) {
    log::Error("unhandled non-standard exception in connection");
  }
}

bool OpenAcceptor(tcp::acceptor* acceptor, const tcp::endpoint& endpoint,
                  bool reuse_port, bool capture_syn, std::string* error) {
  std::error_code ec;
  const auto fail = [&](std::string_view step) {
    *error = std::format("listen {}: {}: {}", FormatEndpoint(endpoint), step,
                         ec.message());
    return false;
  };
  acceptor->open(endpoint.protocol(), ec);
  if (ec) return fail("open");
  acceptor->set_option(tcp::acceptor::reuse_address(true), ec);
  if (ec) return fail("SO_REUSEADDR");
  if (reuse_port && !EnableReusePort(acceptor->native_handle())) {
    ec = std::error_code(errno, std::system_category());
    return fail("SO_REUSEPORT");
  }
  if (capture_syn && !EnableSynCapture(acceptor->native_handle())) {
    log::Debug("TCP_SAVE_SYN unavailable on {}", FormatEndpoint(endpoint));
  }
  acceptor->bind(endpoint, ec);
  if (ec) return fail("bind");
  acceptor->listen(kListenBacklog, ec);
  if (ec) return fail("listen");
  return true;
}

// Client IP as a key (IPv4-mapped addresses unmapped).
std::string ClientIp(const tcp::socket& socket) {
  std::error_code ec;
  asio::ip::address address = socket.remote_endpoint(ec).address();
  if (address.is_v6() && address.to_v6().is_v4_mapped()) {
    address = asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
  }
  return address.to_string();
}

// Per-IP limits before any TLS work: rate of new connections and number of
// open ones. On success `ip` is set when an open-connection slot was taken.
bool AdmitConnection(const tcp::socket& socket, const GatewayContext& context,
                     std::string* ip) {
  const Config& config = *context.config;
  if (config.new_connections_per_ip <= 0 &&
      config.open_connections_per_ip == 0) {
    return true;
  }
  const std::string address = ClientIp(socket);
  Metrics& metrics = GlobalMetrics();
  if (config.new_connections_per_ip > 0) {
    const GcraParams params = GcraParams::FromRate(
        config.new_connections_per_ip,
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            config.new_connections_period)
            .count(),
        config.new_connections_burst);
    const int64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
    if (!context.rate_limit_store->Check("conn\x1f" + address, params, now)
             .allowed) {
      metrics.rejected_ip_connection_rate.Inc();
      return false;
    }
  }
  if (config.open_connections_per_ip > 0) {
    if (!context.connection_counter->Acquire(address,
                                             config.open_connections_per_ip)) {
      metrics.rejected_ip_connections.Inc();
      return false;
    }
    *ip = address;
  }
  return true;
}

// Runs a connection handler and releases its per-IP slot afterwards.
asio::awaitable<void> ServeConnection(tcp::socket socket, bool https,
                                      std::string ip,
                                      const GatewayContext& context) {
  struct Slot {
    ConnectionCounter* counter;
    std::string ip;
    ~Slot() {
      if (!ip.empty()) counter->Release(ip);
    }
  } slot{context.connection_counter, std::move(ip)};
  if (https) {
    co_await HandleHttpsConnection(std::move(socket), context);
  } else {
    co_await HandleHttpConnection(std::move(socket), context);
  }
}

asio::awaitable<void> AcceptLoop(tcp::acceptor& acceptor, bool https,
                                 const GatewayContext& context) {
  constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
  auto executor = co_await asio::this_coro::executor;
  Metrics& metrics = GlobalMetrics();
  while (true) {
    auto [ec, socket] = co_await acceptor.async_accept(kUse);
    if (ec) {
      if (!acceptor.is_open() || ec == asio::error::operation_aborted) {
        co_return;
      }
      log::Warn("accept failed: {}", ec.message());
      // Typically EMFILE: back off instead of spinning.
      asio::steady_timer pause(executor, std::chrono::milliseconds(50));
      co_await pause.async_wait(kUse);
      continue;
    }
    if (std::cmp_greater_equal(metrics.connections_active.Get(),
                               context.config->max_connections)) {
      metrics.rejected_connection_limit.Inc();
      continue;  // `socket` closes here.
    }
    std::string ip;
    if (!AdmitConnection(socket, context, &ip)) continue;
    asio::co_spawn(
        executor,
        ServeConnection(std::move(socket), https, std::move(ip), context),
        LogUnhandled);
  }
}

}  // namespace

bool ResolveEndpoint(const Endpoint& endpoint, tcp::endpoint* out,
                     std::string* error) {
  std::error_code ec;
  const asio::ip::address address = asio::ip::make_address(endpoint.host, ec);
  if (!ec) {
    *out = tcp::endpoint(address, endpoint.port);
    return true;
  }
  asio::io_context io_context;
  tcp::resolver resolver(io_context);
  const auto results =
      resolver.resolve(endpoint.host, std::to_string(endpoint.port), ec);
  if (ec || results.empty()) {
    *error = std::format("cannot resolve {}: {}", endpoint.ToString(),
                         ec ? ec.message() : "no addresses");
    return false;
  }
  *out = results.begin()->endpoint();
  return true;
}

Worker::Worker(int index, GatewayContext shared, const Config& config)
    : index_(index),
      io_context_(1),
      upstream_tls_(asio::ssl::context::tls_client),
      context_(std::move(shared)) {
  upstream_tls_.set_options(asio::ssl::context::no_tlsv1 |
                            asio::ssl::context::no_tlsv1_1);
  if (config.upstream_tls_verify) {
    upstream_tls_.set_default_verify_paths();
    upstream_tls_.set_verify_mode(asio::ssl::verify_peer);
  } else {
    upstream_tls_.set_verify_mode(asio::ssl::verify_none);
  }
  context_.upstream_tls = &upstream_tls_;

  UpstreamSettings upstream;
  upstream.endpoint = context_.upstream_https;
  upstream.tls = &upstream_tls_;
  upstream.verify = config.upstream_tls_verify;
  upstream.connect_timeout = config.upstream_connect_timeout;
  upstream.handshake_timeout = config.tls_handshake_timeout;
  upstream.idle_timeout = config.upstream_idle_timeout;
  upstream.max_connections_per_host = config.upstream_pool_size;
  pool_ = std::make_unique<UpstreamPool>(io_context_.get_executor(), upstream);
  context_.pool = pool_.get();
  context_.proxy_settings.idle_timeout = config.idle_timeout;
}

bool Worker::Listen(const tcp::endpoint& https,
                    const std::optional<tcp::endpoint>& http, bool reuse_port,
                    std::string* error) {
  auto https_acceptor = std::make_unique<tcp::acceptor>(io_context_);
  if (!OpenAcceptor(https_acceptor.get(), https, reuse_port,
                    /*capture_syn=*/true, error)) {
    return false;
  }
  StartAccepting(https_acceptor.get(), /*https=*/true);
  acceptors_.push_back(std::move(https_acceptor));

  if (http) {
    auto http_acceptor = std::make_unique<tcp::acceptor>(io_context_);
    if (!OpenAcceptor(http_acceptor.get(), *http, reuse_port,
                      /*capture_syn=*/true, error)) {
      return false;
    }
    StartAccepting(http_acceptor.get(), /*https=*/false);
    acceptors_.push_back(std::move(http_acceptor));
  }
  return true;
}

bool Worker::ListenMetrics(const tcp::endpoint& endpoint, std::string* error) {
  auto acceptor = std::make_unique<tcp::acceptor>(io_context_);
  if (!OpenAcceptor(acceptor.get(), endpoint, /*reuse_port=*/false,
                    /*capture_syn=*/false, error)) {
    return false;
  }
  asio::co_spawn(io_context_, ServeMetrics(*acceptor), LogUnhandled);
  acceptors_.push_back(std::move(acceptor));
  return true;
}

void Worker::StartAccepting(tcp::acceptor* acceptor, bool https) {
  asio::co_spawn(io_context_, AcceptLoop(*acceptor, https, context_),
                 LogUnhandled);
}

void Worker::Run() {
  thread_ = std::thread([this] {
    try {
      io_context_.run();
    } catch (const std::exception& e) {
      log::Error("worker {} stopped: {}", index_, e.what());
    }
    finished_.store(true);
  });
}

void Worker::StopAccepting() {
  asio::post(io_context_, [this] {
    for (auto& acceptor : acceptors_) {
      std::error_code ec;
      acceptor->close(ec);
    }
    // Pooled connections to Traefik would keep the loop alive otherwise.
    pool_->Drain();
  });
}

void Worker::Stop() { io_context_.stop(); }

void Worker::Join() {
  if (thread_.joinable()) thread_.join();
}

Gateway::Gateway(const Config& config, const CertStore* certificates,
                 EventSink* events, const EventSettings* event_settings,
                 const FingerprintLibrary* library, const LabelStore* labels)
    : config_(config),
      certificates_(certificates),
      events_(events),
      event_settings_(event_settings),
      classifier_(config.passthrough_hosts, config.non_tls),
      scorer_(library, config.policy.suspicious_threshold,
              config.policy.bot_threshold),
      policy_(config.policy),
      labels_(labels) {}

Gateway::~Gateway() {
  Stop();
  Join();
}

bool Gateway::Start(std::string* error) {
  if (!RuleSet::Compile(config_.rules, &rules_, error) ||
      !RateLimitSet::Compile(config_.rate_limits, &rate_limits_, error)) {
    return false;
  }
  GatewayContext shared;
  shared.config = &config_;
  shared.certificates = certificates_;
  shared.classifier = &classifier_;
  shared.scorer = &scorer_;
  shared.policy = &policy_;
  shared.rules = &rules_;
  shared.labels = labels_;
  shared.rate_limits = &rate_limits_;
  shared.rate_limit_store = &rate_limit_store_;
  shared.connection_counter = &connection_counter_;
  shared.events = events_;
  shared.event_settings = event_settings_;
  if (!ResolveEndpoint(config_.upstream_https, &shared.upstream_https, error) ||
      !ResolveEndpoint(config_.upstream_http, &shared.upstream_http, error)) {
    return false;
  }

  tcp::endpoint https;
  std::optional<tcp::endpoint> http;
  std::optional<tcp::endpoint> metrics;
  if (!ResolveEndpoint(config_.listen_https, &https, error)) return false;
  if (config_.listen_http) {
    http.emplace();
    if (!ResolveEndpoint(*config_.listen_http, &*http, error)) return false;
  }
  if (config_.metrics_listen) {
    metrics.emplace();
    if (!ResolveEndpoint(*config_.metrics_listen, &*metrics, error)) {
      return false;
    }
  }

  int count = config_.workers > 0
                  ? config_.workers
                  : static_cast<int>(std::thread::hardware_concurrency());
  if (count <= 0) count = 1;
  const bool reuse_port = SupportsReusePortBalancing();
  if (!reuse_port && count > 1) {
    log::Warn(
        "SO_REUSEPORT load balancing is Linux-only; running a single worker");
    count = 1;
  }

  for (int i = 0; i < count; ++i) {
    auto worker = std::make_unique<Worker>(i, shared, config_);
    if (!worker->Listen(https, http, reuse_port, error)) return false;
    if (i == 0 && metrics && !worker->ListenMetrics(*metrics, error)) {
      return false;
    }
    workers_.push_back(std::move(worker));
  }
  for (auto& worker : workers_) worker->Run();

  log::Info("listening on https={} http={} metrics={} workers={}",
            FormatEndpoint(https), http ? FormatEndpoint(*http) : "off",
            metrics ? FormatEndpoint(*metrics) : "off", count);
  log::Info("upstream https={} http={} proxy_protocol={}",
            FormatEndpoint(shared.upstream_https),
            FormatEndpoint(shared.upstream_http), config_.proxy_protocol);
  return true;
}

void Gateway::StopAccepting() {
  for (auto& worker : workers_) worker->StopAccepting();
}

void Gateway::Stop() {
  for (auto& worker : workers_) worker->Stop();
}

void Gateway::Join() {
  for (auto& worker : workers_) worker->Join();
}

bool Gateway::finished() const {
  for (const auto& worker : workers_) {
    if (!worker->finished()) return false;
  }
  return true;
}

}  // namespace bot_shield
