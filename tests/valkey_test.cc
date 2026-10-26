#include "ratelimit/valkey.h"

#include <fcntl.h>  // IWYU pragma: keep (open on Linux)
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/fcntl.h>  // IWYU pragma: keep (open on macOS)
// kill is POSIX: <signal.h> on Linux, <sys/signal.h> on macOS.
// NOLINTNEXTLINE(modernize-deprecated-headers)
#include <signal.h>      // IWYU pragma: keep
#include <sys/signal.h>  // IWYU pragma: keep
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ratelimit/gcra.h"
#include "ratelimit/store.h"

namespace bot_shield {
namespace {

using std::chrono::milliseconds;

TEST(RespTest, EncodesAndParses) {
  EXPECT_EQ(RespCommand({"GET", "a b"}), "*2\r\n$3\r\nGET\r\n$3\r\na b\r\n");
  RespValue value;
  EXPECT_EQ(RespParse("+OK\r\n", &value), 5);
  EXPECT_EQ(value.type, RespValue::Type::kSimple);
  EXPECT_EQ(value.text, "OK");
  EXPECT_EQ(RespParse(":-42\r\n", &value), 6);
  EXPECT_EQ(value.integer, -42);
  EXPECT_EQ(RespParse("$-1\r\n", &value), 5);
  EXPECT_EQ(value.type, RespValue::Type::kNull);
  EXPECT_EQ(RespParse("$5\r\nhel", &value), 0);  // Incomplete.
  EXPECT_EQ(RespParse("$5\r\nhello\r\n", &value), 11);
  EXPECT_EQ(value.text, "hello");
  EXPECT_EQ(RespParse("*2\r\n:1\r\n*1\r\n$1\r\nx\r\n", &value), 19);
  ASSERT_EQ(value.items.size(), 2u);
  EXPECT_EQ(value.items[1].items[0].text, "x");
  EXPECT_EQ(RespParse("*2\r\n:1\r\n", &value), 0);
  EXPECT_EQ(RespParse("-ERR no\r\n", &value), 9);
  EXPECT_EQ(value.type, RespValue::Type::kError);
  EXPECT_EQ(RespParse("?\r\n", &value), -1);
  EXPECT_EQ(RespParse(":x\r\n", &value), -1);
}

uint16_t FreePort() {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close(fd);
    return 0;
  }
  socklen_t size = sizeof(address);
  getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size);
  close(fd);
  return ntohs(address.sin_port);
}

// A valkey-server (or redis-server) of our own on a free port; tests skip
// without one (CI installs valkey-server).
class ValkeyServer {
 public:
  ValkeyServer() {
    for (const char* name : {"valkey-server", "redis-server"}) {
      for (const char* dir :
           {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"}) {
        const std::string path = std::string(dir) + "/" + name;
        if (std::filesystem::exists(path)) {
          binary_ = path;
          break;
        }
      }
      if (!binary_.empty()) break;
    }
    if (binary_.empty()) return;
    port_ = FreePort();
    pid_ = fork();
    if (pid_ == 0) {
      // Quiet: its log is not the test's output.
      const int null = open("/dev/null", O_WRONLY);
      dup2(null, STDOUT_FILENO);
      dup2(null, STDERR_FILENO);
      const std::string port = std::to_string(port_);
      execl(binary_.c_str(), binary_.c_str(), "--port", port.c_str(), "--bind",
            "127.0.0.1", "--save", "", "--appendonly", "no", "--requirepass",
            "test-secret", nullptr);
      _exit(127);
    }
    // Ready once it answers.
    for (int i = 0; i < 100; ++i) {
      ValkeyConnection connection;
      std::string error;
      if (connection.Connect("127.0.0.1", port_, milliseconds(100), &error)) {
        return;
      }
      std::this_thread::sleep_for(milliseconds(20));
    }
  }
  ~ValkeyServer() {
    if (pid_ > 0) {
      kill(pid_, SIGTERM);
      waitpid(pid_, nullptr, 0);
    }
  }
  ValkeyServer(const ValkeyServer&) = delete;
  ValkeyServer& operator=(const ValkeyServer&) = delete;

  bool available() const { return !binary_.empty() && pid_ > 0; }
  ValkeySettings Settings() const {
    ValkeySettings settings;
    settings.host = "127.0.0.1";
    settings.port = port_;
    settings.password = "test-secret";
    settings.prefix = "test:";
    settings.timeout = milliseconds(500);
    settings.sync_interval = milliseconds(20);
    return settings;
  }

 private:
  std::string binary_;
  uint16_t port_ = 0;
  decltype(fork()) pid_ = -1;
};

bool WaitUp(const ValkeyLimiter& limiter) {
  for (int i = 0; i < 200 && !limiter.available(); ++i) {
    std::this_thread::sleep_for(milliseconds(10));
  }
  return limiter.available();
}

struct StrictAnswer {
  std::optional<GcraResult> result;
  std::size_t refused = 0;
};

StrictAnswer RunStrict(ValkeyLimiter& limiter,
                       const std::vector<StrictCheck>& checks) {
  std::promise<StrictAnswer> promise;
  auto future = promise.get_future();
  const bool queued = limiter.Strict(
      checks,
      [&promise](std::optional<GcraResult> result, std::size_t refused) {
        promise.set_value({result, refused});
      });
  if (!queued) return {};
  return future.get();
}

TEST(ValkeyLimiterTest, StrictIsAtomicAcrossGateways) {
  ValkeyServer server;
  if (!server.available()) GTEST_SKIP() << "no valkey-server";
  RateLimitStore store_a;
  RateLimitStore store_b;
  ValkeyLimiter a(server.Settings(), &store_a);
  ValkeyLimiter b(server.Settings(), &store_b);
  ASSERT_TRUE(WaitUp(a));
  ASSERT_TRUE(WaitUp(b));
  // 2 per minute, burst 2: the third request anywhere is refused.
  const GcraParams params = GcraParams::FromRate(2, int64_t{60'000'000'000}, 2);
  const std::vector<StrictCheck> login = {{"login",
                                           "login\x1f"
                                           "203.0.113.7",
                                           params, 2, 60}};
  StrictAnswer first = RunStrict(a, login);
  ASSERT_TRUE(first.result);
  EXPECT_TRUE(first.result->allowed);
  EXPECT_EQ(first.refused, login.size());
  const StrictAnswer second = RunStrict(b, login);
  ASSERT_TRUE(second.result);
  EXPECT_TRUE(second.result->allowed);
  const StrictAnswer third = RunStrict(a, login);
  ASSERT_TRUE(third.result);
  EXPECT_FALSE(third.result->allowed);
  EXPECT_EQ(third.refused, 0u);
  EXPECT_GT(third.result->retry_after_ns, int64_t{20'000'000'000});
  // Another key is untouched.
  const std::vector<StrictCheck> other = {{"login",
                                           "login\x1f"
                                           "198.51.100.1",
                                           params, 2, 60}};
  const StrictAnswer fresh = RunStrict(b, other);
  ASSERT_TRUE(fresh.result);
  EXPECT_TRUE(fresh.result->allowed);
}

TEST(ValkeyLimiterTest, SyncedGatewaysShareTheLimit) {
  ValkeyServer server;
  if (!server.available()) GTEST_SKIP() << "no valkey-server";
  RateLimitStore store_a;
  RateLimitStore store_b;
  ValkeyLimiter a(server.Settings(), &store_a);
  ValkeyLimiter b(server.Settings(), &store_b);
  ASSERT_TRUE(WaitUp(a));
  ASSERT_TRUE(WaitUp(b));
  const GcraParams params =
      GcraParams::FromRate(10, int64_t{60'000'000'000}, 10);
  const std::string key = "api\x1fk1";
  const auto now = [] {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  };
  // Gateway A uses up the burst locally and reports it.
  for (int i = 0; i < 10; ++i) {
    ASSERT_TRUE(store_a.Check(key, params, now()).allowed);
    a.NoteSynced(key, params);
  }
  std::this_thread::sleep_for(milliseconds(150));
  // Gateway B lets one through locally; its next sync learns A's use.
  ASSERT_TRUE(store_b.Check(key, params, now()).allowed);
  b.NoteSynced(key, params);
  std::this_thread::sleep_for(milliseconds(150));
  EXPECT_FALSE(store_b.Check(key, params, now()).allowed);
}

TEST(ValkeyLimiterTest, DownMeansLocal) {
  ValkeySettings settings;
  settings.host = "127.0.0.1";
  settings.port = FreePort();  // Nothing listens.
  settings.timeout = milliseconds(50);
  RateLimitStore store;
  ValkeyLimiter limiter(settings, &store);
  std::this_thread::sleep_for(milliseconds(100));
  EXPECT_FALSE(limiter.available());
  // Not queued: the caller decides locally.
  EXPECT_FALSE(
      limiter.Strict({}, [](std::optional<GcraResult>, std::size_t) {}));
  limiter.NoteSynced("k", GcraParams::FromRate(1, 1'000'000'000, 1));
}

}  // namespace
}  // namespace bot_shield
