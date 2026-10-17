#include "events/nats_publisher.h"

#include <algorithm>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/post.hpp>
#include <asio/read_until.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <cstddef>
#include <exception>
#include <format>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/log.h"
#include "common/metrics.h"
#include "net/watchdog.h"

namespace bot_shield {
namespace {

using asio::ip::tcp;
// Used by `co_await (a || b)`; clang-tidy does not see operator lookups.
// NOLINTNEXTLINE(misc-unused-using-decls)
using asio::experimental::awaitable_operators::operator||;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);
constexpr auto kConnectTimeout = std::chrono::seconds(5);
constexpr auto kIdleFlush = std::chrono::seconds(1);
constexpr auto kMinBackoff = std::chrono::seconds(1);
constexpr auto kMaxBackoff = std::chrono::seconds(30);
constexpr auto kStopGrace = std::chrono::seconds(1);
constexpr std::size_t kMaxLine = std::size_t{64} * 1024;

}  // namespace

NatsPublisher::NatsPublisher(NatsSettings settings)
    : settings_(std::move(settings)) {}

NatsPublisher::~NatsPublisher() { Stop(); }

std::string NatsPublisher::ConnectCommand(const NatsSettings& settings) {
  nlohmann::json connect = {
      {"verbose", false},     {"pedantic", false}, {"tls_required", false},
      {"name", "bot-shield"}, {"lang", "cpp"},     {"version", "0.1.0"},
      {"protocol", 1},        {"headers", false},  {"no_responders", false},
  };
  if (!settings.token.empty()) connect["auth_token"] = settings.token;
  if (!settings.user.empty()) {
    connect["user"] = settings.user;
    connect["pass"] = settings.password;
  }
  return "CONNECT " + connect.dump() + "\r\n";
}

std::string NatsPublisher::PubFrame(std::string_view subject,
                                    std::string_view payload) {
  return std::format("PUB {} {}\r\n{}\r\n", subject, payload.size(), payload);
}

void NatsPublisher::Start() {
  asio::co_spawn(io_context_, Run(), [](const std::exception_ptr& error) {
    if (!error) return;
    try {
      std::rethrow_exception(error);
    } catch (const std::exception& e) {
      log::Error("nats: publisher stopped: {}", e.what());
    }
  });
  thread_ = std::thread([this] { io_context_.run(); });
}

void NatsPublisher::Stop() {
  if (!thread_.joinable()) return;
  asio::post(io_context_, [this] {
    stopping_ = true;
    wake_timer_.cancel();
    backoff_timer_.cancel();
    // Give the writer a moment to flush, then force everything down.
    stop_timer_.expires_after(kStopGrace);
    stop_timer_.async_wait([this](const std::error_code& ec) {
      if (ec) return;  // Run() finished in time and cancelled us.
      if (socket_ != nullptr) {
        std::error_code ignored;
        socket_->close(ignored);
      }
      io_context_.stop();
    });
  });
  thread_.join();
}

void NatsPublisher::Publish(std::string_view kind, std::string payload) {
  std::string frame =
      PubFrame(std::format("{}.{}", settings_.subject_prefix, kind), payload);
  {
    std::scoped_lock lock(mutex_);
    if (queue_.size() >= settings_.max_queue) {
      GlobalMetrics().events_dropped.Inc();
      return;
    }
    queue_.push_back(std::move(frame));
  }
  Wake();
}

void NatsPublisher::Wake() {
  if (!wake_pending_.exchange(true)) {
    asio::post(io_context_, [this] { wake_timer_.cancel(); });
  }
}

std::string NatsPublisher::TakeBatch(std::size_t* count) {
  std::vector<std::string> frames;
  {
    std::scoped_lock lock(mutex_);
    frames.swap(queue_);
  }
  std::string batch;
  std::size_t size = 0;
  for (const std::string& frame : frames) size += frame.size();
  batch.reserve(size);
  for (const std::string& frame : frames) batch += frame;
  *count = frames.size();
  return batch;
}

asio::awaitable<void> NatsPublisher::Run() {
  auto executor = co_await asio::this_coro::executor;
  auto backoff =
      std::chrono::duration_cast<std::chrono::milliseconds>(kMinBackoff);
  bool first = true;
  while (!stopping_) {
    if (!first) GlobalMetrics().nats_reconnects.Inc();
    first = false;
    tcp::socket socket(executor);
    socket_ = &socket;
    bool connected = false;
    {
      ScopedWatchdog deadline(executor, kConnectTimeout, [&socket] {
        std::error_code ec;
        socket.close(ec);
      });
      auto [ec] = co_await socket.async_connect(settings_.server, kUse);
      connected = !ec;
      if (ec && !stopping_) {
        log::Warn("nats: connect to {}:{} failed: {}",
                  settings_.server.address().to_string(),
                  settings_.server.port(),
                  deadline->expired() ? "timeout" : ec.message());
      }
    }
    if (connected) {
      backoff =
          std::chrono::duration_cast<std::chrono::milliseconds>(kMinBackoff);
      co_await Session(socket);
    }
    socket_ = nullptr;
    if (stopping_) break;
    backoff_timer_.expires_after(backoff);
    co_await backoff_timer_.async_wait(kUse);
    backoff = std::min(
        backoff * 2,
        std::chrono::duration_cast<std::chrono::milliseconds>(kMaxBackoff));
  }
  stop_timer_.cancel();
}

asio::awaitable<void> NatsPublisher::Session(tcp::socket& socket) {
  std::error_code ec;
  socket.set_option(tcp::no_delay(true), ec);

  std::string line;
  auto [read_ec, n] = co_await asio::async_read_until(
      socket, asio::dynamic_buffer(line, kMaxLine), "\r\n", kUse);
  if (read_ec || !line.starts_with("INFO ")) {
    log::Warn("nats: expected INFO from server");
    co_return;
  }
  const std::string hello = ConnectCommand(settings_) + "PING\r\n";
  auto [write_ec, written] =
      co_await asio::async_write(socket, asio::buffer(hello), kUse);
  if (write_ec) co_return;

  log::Info("nats: connected to {}:{}", settings_.server.address().to_string(),
            settings_.server.port());
  GlobalMetrics().nats_connected.Set(1);
  pong_pending_ = false;
  co_await (Reader(socket) || Writer(socket));
  GlobalMetrics().nats_connected.Set(0);
  if (!stopping_) log::Warn("nats: connection lost");
}

asio::awaitable<void> NatsPublisher::Reader(tcp::socket& socket) {
  std::string buffer;
  while (true) {
    auto [ec, n] = co_await asio::async_read_until(
        socket, asio::dynamic_buffer(buffer, kMaxLine), "\r\n", kUse);
    if (ec) co_return;
    const std::string line = buffer.substr(0, n - 2);
    buffer.erase(0, n);
    if (line == "PING") {
      // Writes belong to the writer; ask it to answer.
      pong_pending_ = true;
      wake_timer_.cancel();
    } else if (line.starts_with("-ERR")) {
      log::Warn("nats: server error: {}", line);
    }
  }
}

asio::awaitable<void> NatsPublisher::Writer(tcp::socket& socket) {
  while (true) {
    wake_pending_ = false;
    std::size_t count = 0;
    std::string batch = TakeBatch(&count);
    if (pong_pending_) {
      batch.insert(0, "PONG\r\n");
      pong_pending_ = false;
    }
    if (!batch.empty()) {
      auto [ec, n] =
          co_await asio::async_write(socket, asio::buffer(batch), kUse);
      if (ec) {
        GlobalMetrics().events_dropped.Inc(count);
        co_return;
      }
      GlobalMetrics().events_published.Inc(count);
      continue;
    }
    if (stopping_) {
      std::error_code ec;
      socket.shutdown(tcp::socket::shutdown_send, ec);
      co_return;
    }
    wake_timer_.expires_after(kIdleFlush);
    co_await wake_timer_.async_wait(kUse);
  }
}

}  // namespace bot_shield
