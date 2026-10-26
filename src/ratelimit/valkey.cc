#include "ratelimit/valkey.h"

// fcntl and poll are declared in <fcntl.h> and <poll.h> on Linux and in
// <sys/fcntl.h> and <sys/poll.h> on macOS: include both, keep both.
#include <fcntl.h>  // IWYU pragma: keep
#include <netdb.h>
#include <poll.h>       // IWYU pragma: keep
#include <sys/fcntl.h>  // IWYU pragma: keep
#include <sys/poll.h>   // IWYU pragma: keep
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/hash.h"
#include "common/log.h"
#include "common/metrics.h"
#include "ratelimit/gcra.h"
#include "ratelimit/store.h"

namespace bot_shield {
namespace {

using std::chrono::steady_clock;

// One GCRA step on the server's clock (microseconds), as GcraCheck:
// {allowed, retry_after_us, reset_after_us, remaining}.
constexpr std::string_view kStrictScript = R"(
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local emission = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local tat = tonumber(redis.call('GET', KEYS[1]) or '0')
if tat < now then tat = now end
local allow_at = tat - tolerance
if now < allow_at then
  return {0, allow_at - now, tat - now, 0}
end
local nxt = tat + emission
redis.call('SET', KEYS[1], string.format('%d', nxt), 'PX',
           math.floor((nxt - now) / 1000) + 1000)
return {1, 0, nxt - now, math.floor((now + tolerance + emission - nxt) / emission)}
)";

// Adds a gateway's local count to the shared state; returns how far the
// shared state is ahead of the server's now (microseconds).
constexpr std::string_view kSyncScript = R"(
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local tat = tonumber(redis.call('GET', KEYS[1]) or '0')
if tat < now then tat = now end
tat = tat + tonumber(ARGV[1]) * tonumber(ARGV[2])
redis.call('SET', KEYS[1], string.format('%d', tat), 'PX',
           math.floor((tat - now) / 1000) + 1000)
return tat - now
)";

#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;  // SO_NOSIGPIPE on the socket instead.
#endif

// Before retrying a Valkey that failed.
constexpr std::chrono::seconds kRetryAfter{1};

int64_t Micros(int64_t nanos) { return std::max<int64_t>(1, nanos / 1000); }

// Keys hold addresses and header values (API keys): Valkey gets a hash.
std::string RemoteKey(std::string_view prefix, std::string_view key) {
  return std::string(prefix) + Sha256Hex(key, 32);
}

int64_t RemainingMs(steady_clock::time_point deadline) {
  return std::max<int64_t>(
      0, std::chrono::duration_cast<std::chrono::milliseconds>(
             deadline - steady_clock::now())
             .count());
}

}  // namespace

std::string RespCommand(const std::vector<std::string>& args) {
  std::string out = std::format("*{}\r\n", args.size());
  for (const std::string& arg : args) {
    out += std::format("${}\r\n", arg.size());
    out += arg;
    out += "\r\n";
  }
  return out;
}

int64_t RespParse(std::string_view buffer, RespValue* value) {
  const std::size_t end = buffer.find("\r\n");
  if (buffer.empty() || end == std::string_view::npos) return 0;
  const std::string_view line = buffer.substr(1, end - 1);
  const int64_t header = static_cast<int64_t>(end) + 2;
  int64_t number = 0;
  const auto parse_number = [&] {
    const auto [ptr, ec] =
        std::from_chars(line.data(), line.data() + line.size(), number);
    return ec == std::errc() && ptr == line.data() + line.size();
  };
  switch (buffer[0]) {
    case '+':
    case '-':
      value->type =
          buffer[0] == '+' ? RespValue::Type::kSimple : RespValue::Type::kError;
      value->text = std::string(line);
      return header;
    case ':':
      if (!parse_number()) return -1;
      value->type = RespValue::Type::kInteger;
      value->integer = number;
      return header;
    case '$': {
      if (!parse_number() || number < -1) return -1;
      if (number == -1) {
        value->type = RespValue::Type::kNull;
        return header;
      }
      if (buffer.size() < static_cast<std::size_t>(header + number + 2)) {
        return 0;
      }
      value->type = RespValue::Type::kBulk;
      value->text = std::string(buffer.substr(header, number));
      return header + number + 2;
    }
    case '*': {
      if (!parse_number() || number < -1) return -1;
      if (number == -1) {
        value->type = RespValue::Type::kNull;
        return header;
      }
      value->type = RespValue::Type::kArray;
      value->items.assign(static_cast<std::size_t>(number), RespValue());
      int64_t used = header;
      for (RespValue& item : value->items) {
        const int64_t n = RespParse(buffer.substr(used), &item);
        if (n <= 0) return n;
        used += n;
      }
      return used;
    }
    default:
      return -1;
  }
}

ValkeyConnection::~ValkeyConnection() { Close(); }

void ValkeyConnection::Close() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  buffer_.clear();
}

bool ValkeyConnection::Connect(const std::string& host, uint16_t port,
                               std::chrono::milliseconds timeout,
                               std::string* error) {
  Close();
  timeout_ = timeout;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints,
                  &result) != 0) {
    *error = std::format("cannot resolve {}", host);
    return false;
  }
  const steady_clock::time_point deadline = steady_clock::now() + timeout;
  for (const addrinfo* it = result; it != nullptr; it = it->ai_next) {
    const int fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
#ifdef SO_NOSIGPIPE
    const int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    if (::connect(fd, it->ai_addr, it->ai_addrlen) != 0 &&
        errno != EINPROGRESS) {
      ::close(fd);
      continue;
    }
    pollfd poll_fd{fd, POLLOUT, 0};
    int so_error = 0;
    socklen_t length = sizeof(so_error);
    if (::poll(&poll_fd, 1, static_cast<int>(RemainingMs(deadline))) == 1 &&
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &length) == 0 &&
        so_error == 0) {
      fd_ = fd;
      break;
    }
    ::close(fd);
  }
  freeaddrinfo(result);
  if (fd_ < 0) {
    *error = std::format("cannot connect to {}:{}", host, port);
    return false;
  }
  return true;
}

bool ValkeyConnection::Run(
    const std::vector<std::vector<std::string>>& commands,
    std::vector<RespValue>* replies, std::string* error) {
  replies->clear();
  if (fd_ < 0) {
    *error = "not connected";
    return false;
  }
  const steady_clock::time_point deadline = steady_clock::now() + timeout_;
  std::string out;
  for (const auto& command : commands) out += RespCommand(command);
  std::size_t sent = 0;
  while (sent < out.size()) {
    pollfd poll_fd{fd_, POLLOUT, 0};
    if (::poll(&poll_fd, 1, static_cast<int>(RemainingMs(deadline))) != 1) {
      *error = "write timeout";
      Close();
      return false;
    }
    const ssize_t n =
        ::send(fd_, out.data() + sent, out.size() - sent, kSendFlags);
    if (n <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      *error = std::format("write: {}", std::strerror(errno));
      Close();
      return false;
    }
    if (n > 0) sent += static_cast<std::size_t>(n);
  }
  while (replies->size() < commands.size()) {
    RespValue value;
    const int64_t used = RespParse(buffer_, &value);
    if (used < 0) {
      *error = "malformed reply";
      Close();
      return false;
    }
    if (used > 0) {
      buffer_.erase(0, static_cast<std::size_t>(used));
      replies->push_back(std::move(value));
      continue;
    }
    pollfd poll_fd{fd_, POLLIN, 0};
    if (::poll(&poll_fd, 1, static_cast<int>(RemainingMs(deadline))) != 1) {
      *error = "read timeout";
      Close();
      return false;
    }
    char chunk[4096];
    const ssize_t n = ::recv(fd_, chunk, sizeof(chunk), 0);
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
      *error = n == 0 ? "connection closed" : std::strerror(errno);
      Close();
      return false;
    }
    if (n > 0) buffer_.append(chunk, static_cast<std::size_t>(n));
  }
  return true;
}

ValkeyLimiter::ValkeyLimiter(ValkeySettings settings, RateLimitStore* store)
    : settings_(std::move(settings)),
      store_(store),
      next_sync_(steady_clock::now() + settings_.sync_interval),
      thread_([this](const std::stop_token& stop) { Run(stop); }) {}

ValkeyLimiter::~ValkeyLimiter() {
  thread_.request_stop();
  wake_.notify_all();
}

void ValkeyLimiter::NoteSynced(std::string_view key, const GcraParams& params) {
  SyncShard& shard = sync_[std::hash<std::string_view>{}(key) % kSyncShards];
  const std::scoped_lock lock(shard.mutex);
  Pending& pending = shard.keys[std::string(key)];
  pending.params = params;
  ++pending.count;
}

bool ValkeyLimiter::Strict(std::vector<StrictCheck> checks, StrictDone done) {
  if (!up_.load(std::memory_order_relaxed)) return false;
  {
    const std::scoped_lock lock(mutex_);
    if (queue_.size() >= settings_.max_queue) return false;
    queue_.push_back({std::move(checks), std::move(done)});
  }
  wake_.notify_one();
  return true;
}

bool ValkeyLimiter::EnsureConnected() {
  if (connection_.connected()) return true;
  if (steady_clock::now() < retry_at_) return false;
  std::string error;
  std::vector<RespValue> replies;
  bool ok = connection_.Connect(settings_.host, settings_.port,
                                settings_.timeout, &error);
  if (ok && !settings_.password.empty()) {
    ok = connection_.Run({{"AUTH", settings_.password}}, &replies, &error) &&
         replies[0].type != RespValue::Type::kError;
    if (!ok && error.empty()) error = "AUTH refused";
  }
  if (ok) {
    ok = connection_.Run({{"PING"}}, &replies, &error) &&
         replies[0].type != RespValue::Type::kError;
    if (!ok && error.empty()) error = replies[0].text;
  }
  if (!ok) {
    connection_.Close();
    retry_at_ = steady_clock::now() + kRetryAfter;
    if (up_.exchange(false)) {
      log::Warn(
          "valkey {}:{} down ({}); synced and strict limits act "
          "locally",
          settings_.host, settings_.port, error);
    }
    GlobalMetrics().valkey_up.Set(0);
    return false;
  }
  if (!up_.exchange(true)) {
    log::Info("valkey {}:{} connected", settings_.host, settings_.port);
  }
  GlobalMetrics().valkey_up.Set(1);
  return true;
}

void ValkeyLimiter::RunStrict(Job& job) {
  std::vector<std::vector<std::string>> commands;
  commands.reserve(job.checks.size());
  for (const StrictCheck& check : job.checks) {
    commands.push_back({"EVAL", std::string(kStrictScript), "1",
                        RemoteKey(settings_.prefix, check.key),
                        std::to_string(Micros(check.params.emission_ns)),
                        std::to_string(check.params.tolerance_ns / 1000)});
  }
  std::vector<RespValue> replies;
  std::string error;
  if (!EnsureConnected() || !connection_.Run(commands, &replies, &error)) {
    GlobalMetrics().valkey_errors.Inc();
    job.done(std::nullopt, 0);
    return;
  }
  GcraResult last;
  for (std::size_t i = 0; i < replies.size(); ++i) {
    const RespValue& reply = replies[i];
    if (reply.type != RespValue::Type::kArray || reply.items.size() != 4) {
      GlobalMetrics().valkey_errors.Inc();
      job.done(std::nullopt, 0);
      return;
    }
    GcraResult result;
    result.allowed = reply.items[0].integer == 1;
    result.retry_after_ns = reply.items[1].integer * 1000;
    result.reset_after_ns = reply.items[2].integer * 1000;
    result.remaining = reply.items[3].integer;
    if (!result.allowed) {
      job.done(result, i);
      return;
    }
    last = result;
  }
  job.done(last, job.checks.size());
}

void ValkeyLimiter::Sync() {
  std::vector<std::pair<std::string, Pending>> keys;
  for (SyncShard& shard : sync_) {
    std::unordered_map<std::string, Pending> taken;
    {
      const std::scoped_lock lock(shard.mutex);
      taken.swap(shard.keys);
    }
    for (auto& entry : taken) keys.emplace_back(std::move(entry));
  }
  if (keys.empty() || !EnsureConnected()) return;
  std::vector<std::vector<std::string>> commands;
  commands.reserve(keys.size());
  for (const auto& [key, pending] : keys) {
    commands.push_back({"EVAL", std::string(kSyncScript), "1",
                        RemoteKey(settings_.prefix, key),
                        std::to_string(Micros(pending.params.emission_ns)),
                        std::to_string(pending.count)});
  }
  std::vector<RespValue> replies;
  std::string error;
  const int64_t sent_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                              steady_clock::now().time_since_epoch())
                              .count();
  if (!connection_.Run(commands, &replies, &error)) {
    GlobalMetrics().valkey_errors.Inc();
    return;
  }
  GlobalMetrics().valkey_synced_keys.Inc(keys.size());
  for (std::size_t i = 0; i < replies.size(); ++i) {
    if (replies[i].type != RespValue::Type::kInteger) continue;
    // The shared state on the local clock: what the other gateways used.
    store_->Raise(keys[i].first, sent_ns + replies[i].integer * 1000);
  }
}

void ValkeyLimiter::Run(const std::stop_token& stop) {
  EnsureConnected();
  while (!stop.stop_requested()) {
    std::optional<Job> job;
    {
      std::unique_lock lock(mutex_);
      wake_.wait_until(lock, stop, next_sync_,
                       [this] { return !queue_.empty(); });
      if (stop.stop_requested()) break;
      if (!queue_.empty()) {
        job = std::move(queue_.front());
        queue_.pop_front();
      }
    }
    if (job) RunStrict(*job);
    if (steady_clock::now() >= next_sync_) {
      next_sync_ = steady_clock::now() + settings_.sync_interval;
      Sync();
    }
  }
  // Whoever waits for a strict check decides locally.
  const std::scoped_lock lock(mutex_);
  for (Job& job : queue_) job.done(std::nullopt, 0);
  queue_.clear();
}

}  // namespace bot_shield
