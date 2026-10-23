#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "net/http_client.h"
#include "notify/notifier.h"

namespace bot_shield {
namespace {

using Json = nlohmann::json;

// Records requests; fails the first `failures` of them.
struct FakePost {
  std::mutex mutex;
  std::vector<HttpClientRequest> requests;
  int failures = 0;

  NotifySettings Settings() {
    NotifySettings settings;
    settings.name = "edge-1";
    settings.webhook = "https://hooks.example.com/x";
    settings.retry_delay = std::chrono::milliseconds(1);
    settings.post = [this](const HttpClientRequest& request,
                           std::string* error) {
      const std::scoped_lock lock(mutex);
      requests.push_back(request);
      if (failures > 0) {
        --failures;
        *error = "HTTP 500";
        return false;
      }
      return true;
    };
    return settings;
  }

  std::size_t count() {
    const std::scoped_lock lock(mutex);
    return requests.size();
  }
};

TEST(NotifierTest, Bodies) {
  NotifySettings settings;
  settings.name = "edge-1";
  settings.telegram_chat_id = "-100200";
  const Notification notification{"attack_auto", "shop.example.com",
                                  "under-attack mode on <b>"};
  EXPECT_EQ(OperatorNotifier::Line(settings, notification),
            "bot-shield edge-1: under-attack mode on <b>");
  const Json webhook =
      Json::parse(OperatorNotifier::WebhookBody(settings, notification, 42));
  EXPECT_EQ(webhook["event"], "attack_auto");
  EXPECT_EQ(webhook["host"], "shop.example.com");
  EXPECT_EQ(webhook["text"], "bot-shield edge-1: under-attack mode on <b>");
  EXPECT_EQ(webhook["name"], "edge-1");
  EXPECT_EQ(webhook["ts"], 42);
  EXPECT_TRUE(Json::parse(OperatorNotifier::WebhookBody(
      settings, {"nats_down", "", "x"}, 1))["host"]
                  .is_null());
  const Json telegram =
      Json::parse(OperatorNotifier::TelegramBody(settings, notification));
  EXPECT_EQ(telegram["chat_id"], "-100200");
  EXPECT_EQ(telegram["text"], "bot-shield edge-1: under-attack mode on <b>");
  // Plain text: no parse_mode, so a host name is never markup.
  EXPECT_FALSE(telegram.contains("parse_mode"));
}

TEST(NotifierTest, DeliversToWebhookAndTelegram) {
  FakePost fake;
  NotifySettings settings = fake.Settings();
  settings.telegram_token = "123:ABC";
  settings.telegram_chat_id = "7";
  OperatorNotifier notifier(std::move(settings));
  notifier.Start();
  ASSERT_TRUE(notifier.Send({"reload_failed", "", "rules: bad"}));
  notifier.Flush();
  ASSERT_EQ(fake.count(), 2U);
  EXPECT_EQ(fake.requests[0].url, "https://hooks.example.com/x");
  EXPECT_EQ(fake.requests[0].method, "POST");
  EXPECT_EQ(Json::parse(fake.requests[0].body)["event"], "reload_failed");
  EXPECT_EQ(fake.requests[1].url,
            "https://api.telegram.org/bot123:ABC/sendMessage");
  EXPECT_EQ(Json::parse(fake.requests[1].body)["chat_id"], "7");
}

TEST(NotifierTest, RetriesThenGivesUp) {
  FakePost fake;
  fake.failures = 2;
  OperatorNotifier notifier(fake.Settings());
  notifier.Start();
  notifier.Send({"nats_down", "", "a"});
  notifier.Flush();
  EXPECT_EQ(fake.count(), 3U);  // Two failures, then delivered.
  fake.failures = 10;
  notifier.Send({"nats_up", "", "b"});
  notifier.Flush();
  EXPECT_EQ(fake.count(), 6U);  // Three tries, then dropped.
}

TEST(NotifierTest, DoesNotRepeatTooSoon) {
  FakePost fake;
  NotifySettings settings = fake.Settings();
  settings.repeat_after = std::chrono::hours(1);
  OperatorNotifier notifier(std::move(settings));
  notifier.Start();
  EXPECT_TRUE(notifier.Send({"attack_auto", "a.example", "on"}));
  EXPECT_FALSE(notifier.Send({"attack_auto", "a.example", "on again"}));
  EXPECT_TRUE(notifier.Send({"attack_auto", "b.example", "on"}));
  // Debounced at the source: always sent.
  EXPECT_TRUE(notifier.Send({"nats_down", "", "x", false}));
  EXPECT_TRUE(notifier.Send({"nats_down", "", "x", false}));
  notifier.Flush();
  EXPECT_EQ(fake.count(), 4U);
}

TEST(NotifierTest, OffWithoutDestination) {
  NotifySettings settings;
  OperatorNotifier notifier(std::move(settings));
  notifier.Start();
  EXPECT_FALSE(notifier.Send({"attack_auto", "", "x"}));
}

TEST(NotifierTest, StopDeliversWhatIsQueued) {
  FakePost fake;
  {
    OperatorNotifier notifier(fake.Settings());
    notifier.Start();
    for (int i = 0; i < 5; ++i) {
      notifier.Send({"attack_auto", std::to_string(i), "on"});
    }
    notifier.Stop();
    EXPECT_FALSE(notifier.Send({"attack_auto", "late", "on"}));
  }
  EXPECT_EQ(fake.count(), 5U);
}

TEST(NotifierTest, RunsChecks) {
  FakePost fake;
  OperatorNotifier notifier(fake.Settings());
  std::atomic<int> runs{0};
  notifier.Every(std::chrono::milliseconds(5), [&runs, &notifier] {
    if (runs.fetch_add(1) == 2) notifier.Send({"nats_down", "", "x", false});
  });
  notifier.Start();
  for (int i = 0; i < 400 && fake.count() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  EXPECT_EQ(fake.count(), 1U);
  EXPECT_GE(runs.load(), 3);
}

TEST(NatsWatchTest, ReportsLongOutagesOnce) {
  using std::chrono::seconds;
  const auto t0 = std::chrono::steady_clock::now();
  NatsWatch watch("nats:4222", std::chrono::minutes(1));
  EXPECT_FALSE(watch.Observe(true, 0, t0));
  // A short blip is not news.
  EXPECT_FALSE(watch.Observe(false, 0, t0 + seconds(5)));
  EXPECT_FALSE(watch.Observe(true, 0, t0 + seconds(30)));

  EXPECT_FALSE(watch.Observe(false, 10, t0 + seconds(100)));
  EXPECT_FALSE(watch.Observe(false, 15, t0 + seconds(150)));
  const auto down = watch.Observe(false, 25, t0 + seconds(161));
  ASSERT_TRUE(down);
  EXPECT_EQ(down->event, "nats_down");
  EXPECT_FALSE(down->dedupe);
  EXPECT_EQ(down->text,
            "NATS nats:4222 unreachable for 61s: events are queued, then "
            "dropped (15 dropped so far)");
  EXPECT_FALSE(watch.Observe(false, 30, t0 + seconds(200)));
  const auto up = watch.Observe(true, 40, t0 + seconds(280));
  ASSERT_TRUE(up);
  EXPECT_EQ(up->event, "nats_up");
  EXPECT_EQ(up->text,
            "NATS nats:4222 is reachable again after 3m; 30 events dropped "
            "meanwhile");
  EXPECT_FALSE(watch.Observe(true, 40, t0 + seconds(300)));
}

}  // namespace
}  // namespace bot_shield
