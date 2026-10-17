#include "events/nats_publisher.h"

#include <gtest/gtest.h>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <cstddef>
#include <nlohmann/json.hpp>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace bot_shield {
namespace {

using asio::ip::tcp;

TEST(NatsPublisherTest, Frames) {
  EXPECT_EQ(NatsPublisher::PubFrame("a.b", "{}"), "PUB a.b 2\r\n{}\r\n");
  NatsSettings settings;
  settings.token = "t0k";
  const std::string connect = NatsPublisher::ConnectCommand(settings);
  ASSERT_TRUE(connect.starts_with("CONNECT {"));
  ASSERT_TRUE(connect.ends_with("}\r\n"));
  const auto json = nlohmann::json::parse(connect.substr(8));
  EXPECT_EQ(json["auth_token"], "t0k");
  EXPECT_EQ(json["verbose"], false);
}

// A tiny NATS server on a thread: sends INFO, answers the client's PING,
// pings the client once and records every line it receives.
class FakeNatsServer {
 public:
  FakeNatsServer()
      : acceptor_(io_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)) {
    thread_ = std::thread([this] { Serve(); });
  }
  ~FakeNatsServer() { thread_.join(); }

  FakeNatsServer(const FakeNatsServer&) = delete;
  FakeNatsServer& operator=(const FakeNatsServer&) = delete;

  tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }
  const std::vector<std::string>& lines() const { return lines_; }

 private:
  void Serve() {
    tcp::socket socket = acceptor_.accept();
    asio::write(
        socket,
        asio::buffer(std::string(
            "INFO {\"server_id\":\"test\",\"max_payload\":1048576}\r\n")));
    std::string buffer;
    bool pinged = false;
    while (true) {
      std::error_code ec;
      const std::size_t n =
          asio::read_until(socket, asio::dynamic_buffer(buffer), "\r\n", ec);
      if (ec) return;
      std::string line = buffer.substr(0, n - 2);
      buffer.erase(0, n);
      if (line == "PING") {
        asio::write(socket, asio::buffer(std::string("PONG\r\n")));
        if (!pinged) {
          asio::write(socket, asio::buffer(std::string("PING\r\n")));
          pinged = true;
        }
      }
      if (line.starts_with("PUB ")) {
        // Read the payload line too.
        const std::size_t m =
            asio::read_until(socket, asio::dynamic_buffer(buffer), "\r\n", ec);
        if (ec) return;
        line += " | " + buffer.substr(0, m - 2);
        buffer.erase(0, m);
      }
      lines_.push_back(line);
    }
  }

  asio::io_context io_;
  tcp::acceptor acceptor_;
  std::vector<std::string> lines_;
  std::thread thread_;
};

TEST(NatsPublisherTest, PublishesAndAnswersPing) {
  FakeNatsServer server;
  NatsSettings settings;
  settings.server = server.endpoint();
  settings.subject_prefix = "test.events";
  {
    NatsPublisher publisher(settings);
    publisher.Start();
    publisher.Publish("conn", R"({"n":1})");
    publisher.Publish("req", R"({"n":2})");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    publisher.Stop();
  }
  const auto& lines = server.lines();
  ASSERT_GE(lines.size(), 4u);
  EXPECT_TRUE(lines[0].starts_with("CONNECT {"));
  EXPECT_EQ(lines[1], "PING");
  std::vector<std::string> pubs;
  bool ponged = false;
  for (const std::string& line : lines) {
    if (line.starts_with("PUB ")) pubs.push_back(line);
    if (line == "PONG") ponged = true;
  }
  EXPECT_EQ(pubs,
            (std::vector<std::string>{"PUB test.events.conn 7 | {\"n\":1}",
                                      "PUB test.events.req 7 | {\"n\":2}"}));
  EXPECT_TRUE(ponged);
}

TEST(NatsPublisherTest, DropsWhenQueueIsFullAndStopsWithoutServer) {
  NatsSettings settings;
  // Nothing listens here: connects fail and events stay queued.
  settings.server = tcp::endpoint(asio::ip::make_address("127.0.0.1"), 1);
  settings.max_queue = 2;
  NatsPublisher publisher(settings);
  publisher.Start();
  for (int i = 0; i < 5; ++i) publisher.Publish("conn", "{}");
  const auto started = std::chrono::steady_clock::now();
  publisher.Stop();
  EXPECT_LT(std::chrono::steady_clock::now() - started,
            std::chrono::seconds(3));
}

}  // namespace
}  // namespace bot_shield
