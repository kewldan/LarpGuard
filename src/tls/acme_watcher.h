#ifndef BOT_SHIELD_TLS_ACME_WATCHER_H_
#define BOT_SHIELD_TLS_ACME_WATCHER_H_

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

#include "tls/cert_store.h"

namespace bot_shield {

// Polls Traefik's acme.json and publishes a new CertSnapshot when the file
// changes. Polling (rather than inotify) also works for bind mounts, where
// Traefik's rewrite may not produce events visible in our container, and on
// macOS during development.
class AcmeWatcher {
 public:
  AcmeWatcher(std::string path, std::chrono::milliseconds interval,
              CertStore* store);
  ~AcmeWatcher();

  AcmeWatcher(const AcmeWatcher&) = delete;
  AcmeWatcher& operator=(const AcmeWatcher&) = delete;

  // Loads the file once. Returns false if it is missing or unreadable; the
  // store then keeps its previous snapshot.
  bool LoadNow();

  void Start();
  void Stop();

 private:
  struct FileStamp {
    std::filesystem::file_time_type mtime{};
    std::uintmax_t size = 0;

    friend bool operator==(const FileStamp&, const FileStamp&) = default;
  };

  void Run();
  bool ReadStamp(FileStamp* stamp) const;

  const std::string path_;
  const std::chrono::milliseconds interval_;
  CertStore* const store_;

  FileStamp loaded_stamp_;
  FileStamp failed_stamp_;
  bool has_loaded_ = false;

  std::mutex mutex_;
  std::condition_variable wakeup_;
  bool stopping_ = false;
  std::thread thread_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_TLS_ACME_WATCHER_H_
