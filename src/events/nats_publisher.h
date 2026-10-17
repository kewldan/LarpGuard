#ifndef BOT_SHIELD_EVENTS_NATS_PUBLISHER_H_
#define BOT_SHIELD_EVENTS_NATS_PUBLISHER_H_

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "events/event_sink.h"

namespace bot_shield {

struct NatsSettings {
  asio::ip::tcp::endpoint server;
  // Events go to "<prefix>.<kind>", e.g. botshield.events.conn.
  std::string subject_prefix = "botshield.events";
  std::string token;
  std::string user;
  std::string password;
  // Events buffered while NATS is slow or down; beyond this they are dropped.
  std::size_t max_queue = 100000;
};

// Minimal NATS core-protocol publisher (INFO/CONNECT/PUB/PING/PONG) on its own
// thread. Producers on worker threads only append preformatted frames to a
// bounded queue; the publisher batches them into socket writes and reconnects
// with backoff. Durability is up to the server (a JetStream stream bound to
// the subjects).
class NatsPublisher : public EventSink {
 public:
  explicit NatsPublisher(NatsSettings settings);
  ~NatsPublisher() override;

  NatsPublisher(const NatsPublisher&) = delete;
  NatsPublisher& operator=(const NatsPublisher&) = delete;

  void Start();
  // Flushes what it can within about a second, then stops.
  void Stop();

  void Publish(std::string_view kind, std::string payload) override;

  // The CONNECT line sent after INFO (exposed for tests).
  static std::string ConnectCommand(const NatsSettings& settings);
  // "PUB <subject> <size>\r\n<payload>\r\n".
  static std::string PubFrame(std::string_view subject,
                              std::string_view payload);

 private:
  asio::awaitable<void> Run();
  asio::awaitable<void> Session(asio::ip::tcp::socket& socket);
  asio::awaitable<void> Reader(asio::ip::tcp::socket& socket);
  asio::awaitable<void> Writer(asio::ip::tcp::socket& socket);
  void Wake();
  // Moves all queued frames into one buffer; `count` gets their number.
  std::string TakeBatch(std::size_t* count);

  const NatsSettings settings_;
  asio::io_context io_context_{1};
  asio::steady_timer wake_timer_{io_context_};
  asio::steady_timer backoff_timer_{io_context_};
  asio::steady_timer stop_timer_{io_context_};
  asio::ip::tcp::socket* socket_ = nullptr;  // Current session, io thread only.
  std::thread thread_;

  std::mutex mutex_;
  std::vector<std::string> queue_;
  std::atomic<bool> wake_pending_{false};
  std::atomic<bool> stopping_{false};
  bool pong_pending_ = false;  // io thread only.
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_EVENTS_NATS_PUBLISHER_H_
