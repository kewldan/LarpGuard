#ifndef BOT_SHIELD_NOTIFY_NOTIFIER_H_
#define BOT_SHIELD_NOTIFY_NOTIFIER_H_

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "net/http_client.h"

namespace bot_shield {

struct Config;

// Where operator notifications go ("notify" section).
struct NotifySettings {
  // In every message, to tell gateways apart.
  std::string name;
  // POST of a JSON object; "" = off.
  std::string webhook;
  // Telegram Bot API sendMessage; both or neither.
  std::string telegram_token;
  std::string telegram_chat_id;
  // The same event for the same host is not sent again sooner.
  std::chrono::milliseconds repeat_after{std::chrono::minutes(5)};
  // Pause before trying a failed delivery again.
  std::chrono::milliseconds retry_delay{std::chrono::seconds(5)};
  // Delivery; HttpFetch by default (tests replace it). True on a 2xx.
  std::function<bool(const HttpClientRequest& request, std::string* error)>
      post;

  bool enabled() const { return !webhook.empty() || !telegram_token.empty(); }
};

// The notify settings of a configuration; `name` falls back to the host
// name.
NotifySettings NotifySettingsFrom(const Config& config);

struct Notification {
  // attack_auto, nats_down, nats_up, reload_failed, failopen_on,
  // failopen_off.
  std::string event;
  std::string host;  // "" when it is not about one host.
  std::string text;  // One line for a person.
  // Subject to repeat_after. Paired events (down and back) that are
  // debounced where they come from set false, so the pair stays whole.
  bool dedupe = true;
};

// Sends notifications from its own thread: Send() only queues, so it is
// safe on a worker (rare events only: it takes a lock). A failed delivery
// is tried three times, then logged and dropped. Checks registered with
// Every() run on the same thread.
class OperatorNotifier {
 public:
  static constexpr std::size_t kMaxQueue = 64;

  explicit OperatorNotifier(NotifySettings settings);
  ~OperatorNotifier();
  OperatorNotifier(const OperatorNotifier&) = delete;
  OperatorNotifier& operator=(const OperatorNotifier&) = delete;

  // Nothing is sent before Start (checks do not run either).
  void Start();
  // Delivers what is queued, for a few seconds at most, then stops.
  void Stop();

  // False when dropped: a repeat within repeat_after, a full queue, or
  // no destination configured.
  bool Send(Notification notification);
  // Runs `check` every `interval` on the notifier thread; before Start.
  void Every(std::chrono::milliseconds interval, std::function<void()> check);
  // Blocks until the queue is empty and nothing is being sent (tests).
  void Flush();

  // Request bodies (exposed for tests). The webhook gets {"event", "host",
  // "text", "name", "ts"}: "text" is the whole message, so Slack and
  // Mattermost incoming webhooks show it as is.
  static std::string WebhookBody(const NotifySettings& settings,
                                 const Notification& notification,
                                 int64_t unix_seconds);
  static std::string TelegramBody(const NotifySettings& settings,
                                  const Notification& notification);
  static std::string Line(const NotifySettings& settings,
                          const Notification& notification);

 private:
  struct Check {
    std::chrono::milliseconds interval;
    std::function<void()> run;
    std::chrono::steady_clock::time_point due;
  };

  void Run(const std::stop_token& stop);
  void Deliver(const Notification& notification, const std::stop_token& stop);
  bool PostWithRetries(const HttpClientRequest& request,
                       const std::stop_token& stop, std::string* error);

  const NotifySettings settings_;
  std::mutex mutex_;
  std::condition_variable_any wake_;
  std::condition_variable_any idle_;
  std::deque<Notification> queue_;
  std::map<std::string, std::chrono::steady_clock::time_point> last_sent_;
  std::vector<Check> checks_;
  bool busy_ = false;
  bool stopping_ = false;
  std::optional<std::chrono::steady_clock::time_point> stop_deadline_;
  std::jthread thread_;  // Last: joined first.
};

// Turns the NATS connection state, sampled now and then, into one message
// when it has been down for `down_after` and one when it is back.
class NatsWatch {
 public:
  NatsWatch(std::string server, std::chrono::milliseconds down_after)
      : server_(std::move(server)), down_after_(down_after) {}

  // `dropped`: events dropped so far (a counter).
  std::optional<Notification> Observe(
      bool connected, int64_t dropped,
      std::chrono::steady_clock::time_point now);

 private:
  std::string server_;
  std::chrono::milliseconds down_after_;
  std::optional<std::chrono::steady_clock::time_point> down_since_;
  int64_t dropped_at_down_ = 0;
  bool reported_ = false;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_NOTIFY_NOTIFIER_H_
