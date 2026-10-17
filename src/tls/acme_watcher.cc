#include "tls/acme_watcher.h"

#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

#include "common/log.h"
#include "common/metrics.h"

namespace bot_shield {

AcmeWatcher::AcmeWatcher(std::string path, std::chrono::milliseconds interval,
                         CertStore* store)
    : path_(std::move(path)), interval_(interval), store_(store) {}

AcmeWatcher::~AcmeWatcher() { Stop(); }

bool AcmeWatcher::ReadStamp(FileStamp* stamp) const {
  std::error_code ec;
  stamp->mtime = std::filesystem::last_write_time(path_, ec);
  if (ec) return false;
  stamp->size = std::filesystem::file_size(path_, ec);
  return !ec;
}

bool AcmeWatcher::LoadNow() {
  FileStamp stamp;
  if (!ReadStamp(&stamp)) {
    log::Warn("acme.json: cannot stat {}", path_);
    return false;
  }
  std::ifstream file(path_, std::ios::binary);
  std::stringstream contents;
  contents << file.rdbuf();
  if (!file) {
    log::Warn("acme.json: cannot read {}", path_);
    return false;
  }

  auto snapshot = std::make_shared<CertSnapshot>();
  std::vector<std::string> warnings;
  std::string error;
  Metrics& metrics = GlobalMetrics();
  if (!ParseAcmeJson(contents.str(), snapshot.get(), &warnings, &error)) {
    metrics.acme_reloads_failed.Inc();
    // Traefik may be mid-write; only report each broken version once.
    if (!(stamp == failed_stamp_)) {
      log::Warn("acme.json: {} (keeping previous certificates)", error);
      failed_stamp_ = stamp;
    }
    return false;
  }
  for (const std::string& warning : warnings) {
    log::Warn("acme.json: {}", warning);
  }

  const std::size_t count = snapshot->certificate_count();
  const std::size_t names = snapshot->name_count();
  store_->set_snapshot(std::move(snapshot));
  loaded_stamp_ = stamp;
  has_loaded_ = true;

  metrics.acme_reloads_ok.Inc();
  metrics.certificates.Set(static_cast<int64_t>(count));
  metrics.acme_last_reload_seconds.Set(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  log::Info("acme.json: loaded {} certificates for {} names", count, names);
  return true;
}

void AcmeWatcher::Start() {
  thread_ = std::thread([this] { Run(); });
}

void AcmeWatcher::Stop() {
  {
    std::lock_guard lock(mutex_);
    stopping_ = true;
  }
  wakeup_.notify_all();
  if (thread_.joinable()) thread_.join();
}

void AcmeWatcher::Run() {
  std::unique_lock lock(mutex_);
  while (!wakeup_.wait_for(lock, interval_, [this] { return stopping_; })) {
    lock.unlock();
    FileStamp stamp;
    if (ReadStamp(&stamp) && !(has_loaded_ && stamp == loaded_stamp_)) {
      LoadNow();
    }
    lock.lock();
  }
}

}  // namespace bot_shield
