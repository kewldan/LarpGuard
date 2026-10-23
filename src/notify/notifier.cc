#include "notify/notifier.h"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/log.h"
#include "config/config.h"
#include "config/settings.h"
#include "net/http_client.h"

namespace bot_shield {
namespace {

using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;

constexpr int kAttempts = 3;
constexpr std::chrono::seconds kRequestTimeout{10};
// Stop() delivers what is queued for at most this long.
constexpr std::chrono::seconds kStopGrace{5};
// last_sent_ is pruned of stale keys beyond this many.
constexpr std::size_t kMaxKeys = 1024;

bool DefaultPost(const HttpClientRequest& request, std::string* error) {
  HttpClientResponse response;
  if (!HttpFetch(request, &response, error)) return false;
  if (response.status < 200 || response.status >= 300) {
    *error = std::format("HTTP {}", response.status);
    return false;
  }
  return true;
}

std::string HostName() {
  std::array<char, 256> name{};
  if (::gethostname(name.data(), name.size() - 1) != 0) return "";
  return {name.data()};
}

// Errors may quote the URL, and the Telegram token is part of it.
std::string Scrubbed(std::string text, std::string_view secret) {
  if (secret.empty()) return text;
  for (std::size_t at = text.find(secret); at != std::string::npos;
       at = text.find(secret, at)) {
    text.replace(at, secret.size(), "***");
  }
  return text;
}

std::string Seconds(Clock::duration duration) {
  return FormatDuration(std::chrono::duration_cast<std::chrono::seconds>(
      std::max(duration, Clock::duration::zero())));
}

}  // namespace

NotifySettings NotifySettingsFrom(const Config& config) {
  NotifySettings settings;
  settings.name = config.notify_name.empty() ? HostName() : config.notify_name;
  settings.webhook = config.notify_webhook;
  settings.telegram_token = config.notify_telegram_token;
  settings.telegram_chat_id = config.notify_telegram_chat_id;
  settings.repeat_after = config.notify_repeat_after;
  return settings;
}

OperatorNotifier::OperatorNotifier(NotifySettings settings)
    : settings_([&] {
        if (!settings.post) settings.post = DefaultPost;
        return std::move(settings);
      }()) {}

OperatorNotifier::~OperatorNotifier() { Stop(); }

void OperatorNotifier::Start() {
  if (thread_.joinable() || !settings_.enabled()) return;
  {
    const std::scoped_lock lock(mutex_);
    const auto now = Clock::now();
    for (Check& check : checks_) check.due = now + check.interval;
  }
  thread_ = std::jthread([this](const std::stop_token& stop) { Run(stop); });
}

void OperatorNotifier::Stop() {
  {
    const std::scoped_lock lock(mutex_);
    if (stopping_) return;
    stopping_ = true;
    stop_deadline_ = Clock::now() + kStopGrace;
  }
  wake_.notify_all();
  if (thread_.joinable()) thread_.join();
}

bool OperatorNotifier::Send(Notification notification) {
  if (!settings_.enabled()) return false;
  const std::string key =
      std::format("{}\x1f{}", notification.event, notification.host);
  {
    const std::scoped_lock lock(mutex_);
    if (stopping_ || queue_.size() >= kMaxQueue) return false;
    const auto now = Clock::now();
    if (notification.dedupe) {
      const auto it = last_sent_.find(key);
      if (it != last_sent_.end() && now - it->second < settings_.repeat_after) {
        return false;
      }
      if (last_sent_.size() >= kMaxKeys) {
        std::erase_if(last_sent_, [&](const auto& entry) {
          return now - entry.second >= settings_.repeat_after;
        });
      }
      last_sent_[key] = now;
    }
    queue_.push_back(std::move(notification));
  }
  wake_.notify_one();
  return true;
}

void OperatorNotifier::Every(std::chrono::milliseconds interval,
                             std::function<void()> check) {
  const std::scoped_lock lock(mutex_);
  checks_.push_back(Check{interval, std::move(check), {}});
}

void OperatorNotifier::Flush() {
  std::unique_lock lock(mutex_);
  idle_.wait(lock, [this] { return queue_.empty() && !busy_; });
}

std::string OperatorNotifier::Line(const NotifySettings& settings,
                                   const Notification& notification) {
  return settings.name.empty()
             ? std::format("bot-shield: {}", notification.text)
             : std::format("bot-shield {}: {}", settings.name,
                           notification.text);
}

std::string OperatorNotifier::WebhookBody(const NotifySettings& settings,
                                          const Notification& notification,
                                          int64_t unix_seconds) {
  return Json{{"event", notification.event},
              {"host", notification.host.empty() ? Json(nullptr)
                                                 : Json(notification.host)},
              {"text", Line(settings, notification)},
              {"name", settings.name},
              {"ts", unix_seconds}}
      .dump(-1, ' ', false, Json::error_handler_t::replace);
}

std::string OperatorNotifier::TelegramBody(const NotifySettings& settings,
                                           const Notification& notification) {
  // Plain text (no parse_mode): host names and errors are shown as they
  // are, never as markup.
  return Json{{"chat_id", settings.telegram_chat_id},
              {"text", Line(settings, notification)},
              {"disable_web_page_preview", true}}
      .dump(-1, ' ', false, Json::error_handler_t::replace);
}

void OperatorNotifier::Run(const std::stop_token& stop) {
  std::unique_lock lock(mutex_);
  while (!stop.stop_requested()) {
    auto next = Clock::now() + std::chrono::hours(1);
    for (const Check& check : checks_) next = std::min(next, check.due);
    wake_.wait_until(lock, stop, next,
                     [this] { return !queue_.empty() || stopping_; });
    if (stop.stop_requested()) return;

    if (!stopping_) {
      const auto now = Clock::now();
      std::vector<const std::function<void()>*> due;
      for (Check& check : checks_) {
        if (check.due > now) continue;
        due.push_back(&check.run);
        check.due = now + check.interval;
      }
      if (!due.empty()) {
        // Checks call Send(), which takes the lock.
        lock.unlock();
        for (const auto* run : due) (*run)();
        lock.lock();
      }
    }

    if (queue_.empty()) {
      idle_.notify_all();
      if (stopping_) return;
      continue;
    }
    if (stop_deadline_ && Clock::now() >= *stop_deadline_) {
      log::Warn("notify: {} message(s) not sent before shutdown",
                queue_.size());
      queue_.clear();
      idle_.notify_all();
      return;
    }
    Notification notification = std::move(queue_.front());
    queue_.pop_front();
    busy_ = true;
    lock.unlock();
    Deliver(notification, stop);
    lock.lock();
    busy_ = false;
    if (queue_.empty()) idle_.notify_all();
  }
}

bool OperatorNotifier::PostWithRetries(const HttpClientRequest& request,
                                       const std::stop_token& stop,
                                       std::string* error) {
  for (int attempt = 1;; ++attempt) {
    HttpClientRequest current = request;
    {
      const std::scoped_lock lock(mutex_);
      if (stop_deadline_) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            *stop_deadline_ - Clock::now());
        if (left <= std::chrono::milliseconds::zero()) return false;
        current.timeout = std::min(current.timeout, left);
      }
    }
    if (settings_.post(current, error)) return true;
    if (attempt == kAttempts || stop.stop_requested()) return false;
    std::unique_lock lock(mutex_);
    // No retries once stopping: what is left gets one try each.
    if (wake_.wait_for(lock, stop, settings_.retry_delay,
                       [this] { return stopping_; })) {
      return false;
    }
  }
}

void OperatorNotifier::Deliver(const Notification& notification,
                               const std::stop_token& stop) {
  HttpClientRequest request;
  request.method = "POST";
  request.headers = {{"content-type", "application/json"}};
  request.timeout = kRequestTimeout;
  request.max_body = std::size_t{64} << 10;
  request.max_redirects = 0;
  request.stop = stop;
  std::string error;
  if (!settings_.webhook.empty()) {
    request.url = settings_.webhook;
    request.body =
        WebhookBody(settings_, notification,
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());
    if (!PostWithRetries(request, stop, &error)) {
      // The URL may carry a token (Slack and similar): not logged.
      log::Warn("notify: webhook failed for {}: {}", notification.event,
                Scrubbed(error, settings_.webhook));
    }
  }
  if (!settings_.telegram_token.empty()) {
    request.url = std::format("https://api.telegram.org/bot{}/sendMessage",
                              settings_.telegram_token);
    request.body = TelegramBody(settings_, notification);
    if (!PostWithRetries(request, stop, &error)) {
      log::Warn("notify: telegram failed for {}: {}", notification.event,
                Scrubbed(error, settings_.telegram_token));
    }
  }
}

std::optional<Notification> NatsWatch::Observe(bool connected, int64_t dropped,
                                               Clock::time_point now) {
  if (connected) {
    if (!down_since_) return std::nullopt;
    const auto since = *down_since_;
    const bool reported = reported_;
    down_since_.reset();
    reported_ = false;
    if (!reported) return std::nullopt;
    return Notification{
        "nats_up", "",
        std::format("NATS {} is reachable again after {}; {} events dropped "
                    "meanwhile",
                    server_, Seconds(now - since), dropped - dropped_at_down_),
        false};
  }
  if (!down_since_) {
    down_since_ = now;
    dropped_at_down_ = dropped;
    return std::nullopt;
  }
  if (reported_ || now - *down_since_ < down_after_) return std::nullopt;
  reported_ = true;
  return Notification{
      "nats_down", "",
      std::format("NATS {} unreachable for {}: events are queued, then "
                  "dropped ({} dropped so far)",
                  server_, Seconds(now - *down_since_),
                  dropped - dropped_at_down_),
      false};
}

}  // namespace bot_shield
