#ifndef BOT_SHIELD_DOCKER_WATCHER_H_
#define BOT_SHIELD_DOCKER_WATCHER_H_

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "docker/labels.h"

namespace bot_shield {

// Polls the Docker Engine API for running containers and publishes their
// botshield.* label policies. Polling (not the event stream) keeps the
// client trivial and survives Docker restarts; work is skipped while no
// container name or label changed. On errors the previous policies stay.
class DockerWatcher {
 public:
  DockerWatcher(std::string socket_path, std::chrono::milliseconds interval,
                LabelStore* store);
  ~DockerWatcher();

  DockerWatcher(const DockerWatcher&) = delete;
  DockerWatcher& operator=(const DockerWatcher&) = delete;

  // One poll; false if Docker could not be read.
  bool PollNow();
  void Start();
  void Stop();

 private:
  void Run();

  const std::string socket_path_;
  const std::chrono::milliseconds interval_;
  LabelStore* const store_;
  // Container names and labels of the last applied poll.
  std::string last_digest_;
  std::string last_error_;

  std::mutex mutex_;
  std::condition_variable wakeup_;
  bool stopping_ = false;
  std::thread thread_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_DOCKER_WATCHER_H_
