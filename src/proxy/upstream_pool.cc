#include "proxy/upstream_pool.h"

#include <openssl/ssl.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl/host_name_verification.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/log.h"
#include "common/metrics.h"
#include "net/watchdog.h"
#include "proxy/exchange.h"
#include "proxy/h2_upstream.h"

namespace bot_shield {
namespace {

using asio::ip::tcp;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr auto kDrainPoll = std::chrono::milliseconds(200);

std::string SelectedAlpn(const SSL* ssl) {
  const uint8_t* data = nullptr;
  unsigned size = 0;
  SSL_get0_alpn_selected(ssl, &data, &size);
  return {reinterpret_cast<const char*>(data), size};
}

}  // namespace

UpstreamPool::UpstreamPool(asio::any_io_executor executor,
                           UpstreamSettings settings)
    : executor_(std::move(executor)),
      settings_(std::move(settings)),
      drain_timer_(executor_) {}

UpstreamPool::~UpstreamPool() {
  for (auto& [name, slots] : slots_) {
    for (auto& slot : slots) {
      if (slot->connection) slot->connection->Close();
    }
  }
}

std::size_t UpstreamPool::Load(const Slot& slot) {
  if (slot.connecting) return slot.pending.size();
  if (!slot.connection || !slot.connection->usable()) {
    return std::numeric_limits<std::size_t>::max();
  }
  return slot.connection->open_streams();
}

void UpstreamPool::Dispatch(const std::string& server_name,
                            const std::shared_ptr<Exchange>& exchange) {
  auto& slots = slots_[server_name];
  std::erase_if(slots, [](const std::shared_ptr<Slot>& slot) {
    return !slot->connecting &&
           (!slot->connection || slot->connection->closed());
  });

  std::shared_ptr<Slot> best;
  for (const auto& slot : slots) {
    if (!best || Load(*slot) < Load(*best)) best = slot;
  }
  const bool full = !best || Load(*best) >= settings_.streams_per_connection;
  if (full && slots.size() < settings_.max_connections_per_host && !draining_) {
    best = std::make_shared<Slot>();
    slots.push_back(best);
    asio::co_spawn(executor_, Establish(best, server_name), asio::detached);
  }
  if (!best || Load(*best) == std::numeric_limits<std::size_t>::max()) {
    exchange->FailUpstream();
    return;
  }

  if (best->connecting) {
    best->pending.push_back(exchange);
    std::weak_ptr<Slot> weak = best;
    Exchange* raw = exchange.get();
    exchange->cancel_upstream = [weak, raw] {
      if (auto slot = weak.lock()) {
        std::erase_if(slot->pending, [raw](const std::shared_ptr<Exchange>& e) {
          return e.get() == raw;
        });
      }
    };
    return;
  }
  best->connection->Submit(exchange);
}

asio::awaitable<std::unique_ptr<UpstreamTlsTransport>> UpstreamPool::ConnectTls(
    const std::string& server_name, std::string_view alpn) {
  tcp::socket socket(executor_);
  {
    ScopedWatchdog deadline(executor_, settings_.connect_timeout, [&socket] {
      std::error_code ec;
      socket.close(ec);
    });
    auto [ec] = co_await socket.async_connect(settings_.endpoint, kUse);
    if (ec) {
      GlobalMetrics().upstream_connect_failures.Inc();
      log::Warn("upstream: connect to {}:{} failed: {}",
                settings_.endpoint.address().to_string(),
                settings_.endpoint.port(),
                deadline->expired() ? "timeout" : ec.message());
      co_return nullptr;
    }
  }
  std::error_code ignored;
  socket.set_option(tcp::no_delay(true), ignored);

  asio::ssl::stream<tcp::socket> stream(std::move(socket), *settings_.tls);
  SSL_set_tlsext_host_name(stream.native_handle(), server_name.c_str());
  std::vector<uint8_t> wire;
  wire.push_back(static_cast<uint8_t>(alpn.size()));
  wire.insert(wire.end(), alpn.begin(), alpn.end());
  SSL_set_alpn_protos(stream.native_handle(), wire.data(), wire.size());
  if (settings_.verify) {
    stream.set_verify_callback(asio::ssl::host_name_verification(server_name));
  }
  {
    ScopedWatchdog deadline(executor_, settings_.handshake_timeout, [&stream] {
      std::error_code ec;
      stream.lowest_layer().close(ec);
    });
    auto [ec] =
        co_await stream.async_handshake(asio::ssl::stream_base::client, kUse);
    if (ec) {
      GlobalMetrics().tls_handshake_failures_upstream.Inc();
      log::Warn("upstream: TLS handshake for {} failed: {}", server_name,
                deadline->expired() ? "timeout" : ec.message());
      co_return nullptr;
    }
  }
  const std::string negotiated = SelectedAlpn(stream.native_handle());
  // An HTTP/1.1 upstream may omit ALPN entirely.
  if (negotiated != alpn && !(alpn == "http/1.1" && negotiated.empty())) {
    GlobalMetrics().alpn_mismatches.Inc();
    log::Warn("upstream: {} negotiated ALPN '{}' instead of '{}'", server_name,
              negotiated, alpn);
    co_return nullptr;
  }
  co_return std::make_unique<UpstreamTlsTransport>(std::move(stream));
}

asio::awaitable<void> UpstreamPool::Establish(std::shared_ptr<Slot> slot,
                                              std::string server_name) {
  std::unique_ptr<UpstreamTlsTransport> transport =
      co_await ConnectTls(server_name, "h2");
  slot->connecting = false;
  if (!transport) {
    std::vector<std::shared_ptr<Exchange>> pending;
    pending.swap(slot->pending);
    for (const auto& exchange : pending) exchange->FailUpstream();
    co_return;
  }
  slot->connection = H2UpstreamConnection::Create(std::move(transport),
                                                  settings_.idle_timeout);
  slot->connection->Start();
  GlobalMetrics().upstream_connections_opened.Inc();
  std::vector<std::shared_ptr<Exchange>> pending;
  pending.swap(slot->pending);
  for (const auto& exchange : pending) {
    if (!exchange->client_cancelled && !exchange->local) {
      slot->connection->Submit(exchange);
    }
  }
}

asio::awaitable<std::unique_ptr<UpstreamTlsTransport>>
UpstreamPool::ConnectHttp1(const std::string& server_name) {
  co_return co_await ConnectTls(server_name, "http/1.1");
}

void UpstreamPool::Drain() {
  if (draining_) return;
  draining_ = true;
  asio::co_spawn(executor_, DrainLoop(), asio::detached);
}

asio::awaitable<void> UpstreamPool::DrainLoop() {
  while (true) {
    bool any_open = false;
    for (auto& [name, slots] : slots_) {
      for (auto& slot : slots) {
        if (!slot->connection || slot->connection->closed()) continue;
        if (slot->connection->open_streams() == 0) {
          slot->connection->Close();
        } else {
          any_open = true;
        }
      }
    }
    if (!any_open) co_return;
    drain_timer_.expires_after(kDrainPoll);
    auto [ec] = co_await drain_timer_.async_wait(kUse);
    if (ec) co_return;
  }
}

}  // namespace bot_shield
