#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <utility>

#include "common/systemd.h"
#include "config/config.h"
#include "server/health.h"
#include "watchdog/fail_open.h"

namespace bot_shield {
namespace {

using Change = FailOpenSwitch::Change;

TEST(HeartbeatsTest, ReportsStalledWorkers) {
  Heartbeats beats(3, 1000);
  EXPECT_EQ(beats.Stalled(1000 + Heartbeats::kMaxAge.count()), -1);
  beats.Beat(0, 6000);
  beats.Beat(2, 6000);
  EXPECT_EQ(beats.Stalled(6001), 1);
  beats.Beat(1, 6001);
  EXPECT_EQ(beats.Stalled(6002), -1);
  beats.Beat(7, 1);  // Out of range: ignored.
  EXPECT_EQ(beats.Stalled(20000), 0);
}

TEST(FailOpenSwitchTest, NeedsConsecutiveResults) {
  FailOpenSwitch fail_open(3, 2);
  EXPECT_FALSE(fail_open.open().has_value());
  // The first decision is applied even from the unknown state.
  EXPECT_EQ(fail_open.Observe(true), Change::kNone);
  EXPECT_EQ(fail_open.Observe(true), Change::kClose);
  fail_open.Applied(Change::kClose);
  EXPECT_EQ(fail_open.open(), false);
  EXPECT_EQ(fail_open.Observe(true), Change::kNone);

  EXPECT_EQ(fail_open.Observe(false), Change::kNone);
  EXPECT_EQ(fail_open.Observe(false), Change::kNone);
  EXPECT_EQ(fail_open.Observe(true), Change::kNone);  // Resets the count.
  EXPECT_EQ(fail_open.Observe(false), Change::kNone);
  EXPECT_EQ(fail_open.Observe(false), Change::kNone);
  EXPECT_EQ(fail_open.Observe(false), Change::kOpen);
  // Not applied (command failed): asked again.
  EXPECT_EQ(fail_open.Observe(false), Change::kOpen);
  fail_open.Applied(Change::kOpen);
  EXPECT_EQ(fail_open.open(), true);
  EXPECT_EQ(fail_open.Observe(false), Change::kNone);
  EXPECT_EQ(fail_open.Observe(true), Change::kNone);
  EXPECT_EQ(fail_open.Observe(true), Change::kClose);
}

TEST(FailOpenSwitchTest, StartsOpenWhenTheGatewayIsDown) {
  FailOpenSwitch fail_open(2, 5);
  EXPECT_EQ(fail_open.Observe(false), Change::kNone);
  EXPECT_EQ(fail_open.Observe(false), Change::kOpen);
}

// One-shot HTTP server answering with `response`.
class OneShotServer {
 public:
  explicit OneShotServer(std::string response)
      : acceptor_(io_context_, {asio::ip::make_address("127.0.0.1"), 0}),
        thread_([this, response = std::move(response)] {
          asio::ip::tcp::socket socket(io_context_);
          acceptor_.accept(socket);
          std::string request;
          asio::read_until(socket, asio::dynamic_buffer(request), "\r\n\r\n");
          asio::write(socket, asio::buffer(response));
        }) {}
  ~OneShotServer() { thread_.join(); }
  Endpoint endpoint() const {
    return {"127.0.0.1", acceptor_.local_endpoint().port()};
  }

 private:
  asio::io_context io_context_;
  asio::ip::tcp::acceptor acceptor_;
  std::thread thread_;
};

TEST(ProbeHealthTest, AcceptsOnly200) {
  std::string detail;
  {
    OneShotServer server(
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"
        "ok\n");
    EXPECT_TRUE(
        ProbeHealth(server.endpoint(), std::chrono::seconds(2), &detail));
    EXPECT_EQ(detail, "HTTP/1.1 200 OK");
  }
  {
    OneShotServer server(
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    EXPECT_FALSE(
        ProbeHealth(server.endpoint(), std::chrono::seconds(2), &detail));
    EXPECT_EQ(detail, "HTTP/1.1 503 Service Unavailable");
  }
  // Nothing listening.
  asio::io_context io_context;
  asio::ip::tcp::acceptor closed(io_context,
                                 {asio::ip::make_address("127.0.0.1"), 0});
  const Endpoint nobody{"127.0.0.1", closed.local_endpoint().port()};
  closed.close();
  EXPECT_FALSE(ProbeHealth(nobody, std::chrono::seconds(2), &detail));
  EXPECT_FALSE(detail.empty());
}

TEST(ProbeHealthTest, TimesOut) {
  asio::io_context io_context;
  // Listens but never answers.
  asio::ip::tcp::acceptor silent(io_context,
                                 {asio::ip::make_address("127.0.0.1"), 0});
  const Endpoint endpoint{"127.0.0.1", silent.local_endpoint().port()};
  std::string detail;
  const auto started = std::chrono::steady_clock::now();
  EXPECT_FALSE(ProbeHealth(endpoint, std::chrono::milliseconds(200), &detail));
  EXPECT_EQ(detail, "no answer within 200 ms");
  EXPECT_LT(std::chrono::steady_clock::now() - started,
            std::chrono::seconds(2));
}

TEST(SystemdNotifierTest, SendsDatagrams) {
  const std::string path = (std::filesystem::temp_directory_path() /
                            ("bs-notify-" + std::to_string(getpid()) + ".sock"))
                               .string();
  std::filesystem::remove(path);
  const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  ASSERT_GE(fd, 0);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  ASSERT_LT(path.size(), sizeof(address.sun_path));
  std::memcpy(address.sun_path, path.data(), path.size());
  ASSERT_EQ(
      bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)),
      0);

  const SystemdNotifier notifier(path);
  EXPECT_TRUE(notifier.Notify("READY=1"));
  char buffer[64] = {};
  const ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
  EXPECT_EQ(std::string(buffer, n > 0 ? n : 0), "READY=1");
  close(fd);
  std::filesystem::remove(path);
  EXPECT_FALSE(SystemdNotifier("/nonexistent/notify.sock").Notify("X=1"));
}

TEST(SystemdNotifierTest, ReadsWatchdogInterval) {
  setenv("WATCHDOG_USEC", "10000000", 1);
  unsetenv("WATCHDOG_PID");
  EXPECT_EQ(SystemdNotifier::WatchdogInterval(), std::chrono::seconds(5));
  setenv("WATCHDOG_PID", std::to_string(getpid() + 1).c_str(), 1);
  EXPECT_FALSE(SystemdNotifier::WatchdogInterval().has_value());
  unsetenv("WATCHDOG_PID");
  setenv("WATCHDOG_USEC", "junk", 1);
  EXPECT_FALSE(SystemdNotifier::WatchdogInterval().has_value());
  unsetenv("WATCHDOG_USEC");
  EXPECT_FALSE(SystemdNotifier::WatchdogInterval().has_value());
}

}  // namespace
}  // namespace bot_shield
