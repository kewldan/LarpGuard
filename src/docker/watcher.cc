#include "docker/watcher.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "common/log.h"
#include "common/metrics.h"
#include "docker/client.h"
#include "docker/labels.h"

namespace bot_shield {
namespace {

constexpr auto kRequestTimeout = std::chrono::seconds(5);

}  // namespace

DockerWatcher::DockerWatcher(std::string socket_path,
                             std::chrono::milliseconds interval,
                             LabelStore* store)
    : socket_path_(std::move(socket_path)),
      interval_(interval),
      store_(store) {}

DockerWatcher::~DockerWatcher() { Stop(); }

bool DockerWatcher::PollNow() {
  std::string body;
  std::string error;
  std::vector<ContainerInfo> containers;
  if (!DockerGet(socket_path_, "/containers/json", kRequestTimeout, &body,
                 &error) ||
      !ParseContainerList(body, &containers, &error)) {
    GlobalMetrics().docker_polls_failed.Inc();
    if (error != last_error_) {
      log::Warn("{} (keeping previous label policies)", error);
      last_error_ = error;
    }
    return false;
  }
  if (!last_error_.empty()) {
    log::Info("docker: reachable again at {}", socket_path_);
    last_error_.clear();
  }
  // Only names and labels matter: fields such as "Status" ("Up 5 seconds")
  // change on every poll.
  std::string digest;
  for (const ContainerInfo& container : containers) {
    digest += container.name;
    digest.push_back('\0');
    for (const auto& [key, value] : container.labels) {
      digest += key;
      digest.push_back('=');
      digest += value;
      digest.push_back('\0');
    }
    digest.push_back('\n');
  }
  if (digest == last_digest_) return true;
  last_digest_ = std::move(digest);

  std::vector<std::string> warnings;
  std::shared_ptr<const LabelPolicies> policies =
      LabelPolicies::Build(containers, &warnings);
  for (const std::string& warning : warnings) log::Warn("labels: {}", warning);
  log::Info("labels: {} containers, {} hosts, {} rate limits",
            containers.size(), policies->host_count(),
            policies->rate_limit_count());
  GlobalMetrics().label_hosts.Set(static_cast<int64_t>(policies->host_count()));
  store_->set_snapshot(std::move(policies));
  return true;
}

void DockerWatcher::Start() {
  thread_ = std::thread([this] { Run(); });
}

void DockerWatcher::Stop() {
  {
    std::scoped_lock lock(mutex_);
    stopping_ = true;
  }
  wakeup_.notify_all();
  if (thread_.joinable()) thread_.join();
}

void DockerWatcher::Run() {
  std::unique_lock lock(mutex_);
  while (!wakeup_.wait_for(lock, interval_, [this] { return stopping_; })) {
    lock.unlock();
    PollNow();
    lock.lock();
  }
}

}  // namespace bot_shield
