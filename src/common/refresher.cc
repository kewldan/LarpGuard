#include "common/refresher.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <iterator>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/log.h"
#include "net/http_client.h"

namespace bot_shield {
namespace {

bool ReadFile(const std::string& path, std::string* out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return false;
  out->assign(std::istreambuf_iterator<char>(file),
              std::istreambuf_iterator<char>());
  return !file.bad();
}

// Write-then-rename, so a crash never leaves half a cache file.
bool WriteFileAtomically(const std::string& path, std::string_view data,
                         std::string* error) {
  const std::string temporary = path + ".tmp";
  {
    std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!file) {
      *error = std::format("cannot write {}", temporary);
      return false;
    }
  }
  std::error_code rename_error;
  std::filesystem::rename(temporary, path, rename_error);
  if (rename_error) {
    *error = std::format("cannot replace {}: {}", path, rename_error.message());
    return false;
  }
  return true;
}

}  // namespace

bool FetchUrl(const std::string& url, std::size_t max_size, std::string* data,
              std::string* error) {
  HttpClientRequest request;
  request.url = url;
  request.max_body = max_size;
  request.timeout = std::chrono::seconds(120);
  HttpClientResponse response;
  if (!HttpFetch(request, &response, error)) return false;
  if (response.status != 200) {
    *error = std::format("{}: HTTP {}", url, response.status);
    return false;
  }
  *data = std::move(response.body);
  return true;
}

DataRefresher::DataRefresher(std::vector<RefreshSource> sources) {
  for (RefreshSource& source : sources) {
    if (!source.fetch) source.fetch = FetchUrl;
    states_.push_back(State{std::move(source), {}});
  }
}

DataRefresher::~DataRefresher() {
  if (thread_.joinable()) {
    thread_.request_stop();
    wake_.notify_all();
  }
}

void DataRefresher::Start() {
  if (states_.empty() || thread_.joinable()) return;
  thread_ = std::jthread([this](const std::stop_token& stop) { Run(stop); });
}

void DataRefresher::RefreshNow() {
  {
    const std::scoped_lock lock(mutex_);
    refresh_now_ = true;
  }
  wake_.notify_all();
}

void DataRefresher::WaitForPass(int passes) {
  std::unique_lock lock(mutex_);
  pass_done_.wait(lock, [&] { return passes_ >= passes; });
}

void DataRefresher::LoadCache(State* state) {
  const RefreshSource& source = state->source;
  state->due = std::chrono::system_clock::now();
  if (source.cache_file.empty()) return;
  std::string data;
  if (!ReadFile(source.cache_file, &data)) return;
  std::string error;
  if (!source.apply(data, &error)) {
    log::Warn("{}: cached {} ignored: {}", source.name, source.cache_file,
              error);
    return;
  }
  std::error_code time_error;
  const auto written =
      std::filesystem::last_write_time(source.cache_file, time_error);
  if (!time_error) {
    // Age by the file clock (no portable clock_cast yet).
    const auto age = std::chrono::duration_cast<std::chrono::seconds>(
        std::filesystem::file_time_type::clock::now() - written);
    state->due = std::chrono::system_clock::now() - age + source.refresh;
  }
  log::Info("{}: loaded cached copy from {}", source.name, source.cache_file);
}

void DataRefresher::Download(State* state) {
  const RefreshSource& source = state->source;
  std::string data;
  std::string error;
  const auto now = std::chrono::system_clock::now();
  if (!source.fetch(source.url, source.max_size, &data, &error) ||
      !source.apply(data, &error)) {
    log::Warn("{}: update failed, retrying in {}s: {}", source.name,
              source.retry.count(), error);
    state->due = now + source.retry;
    return;
  }
  state->due = now + source.refresh;
  log::Info("{}: updated from {} ({} bytes)", source.name, source.url,
            data.size());
  if (!source.cache_file.empty() &&
      !WriteFileAtomically(source.cache_file, data, &error)) {
    log::Warn("{}: {}", source.name, error);
  }
}

void DataRefresher::Run(const std::stop_token& stop) {
  for (State& state : states_) {
    if (stop.stop_requested()) return;
    LoadCache(&state);
  }
  while (!stop.stop_requested()) {
    bool now_requested = false;
    {
      const std::scoped_lock lock(mutex_);
      now_requested = std::exchange(refresh_now_, false);
    }
    const auto now = std::chrono::system_clock::now();
    for (State& state : states_) {
      if (stop.stop_requested()) return;
      if (now_requested || state.due <= now) Download(&state);
    }
    // Wake at least hourly: clocks jump, and max() would overflow waits.
    auto next = std::chrono::system_clock::now() + std::chrono::hours(1);
    for (const State& state : states_) next = std::min(next, state.due);
    std::unique_lock lock(mutex_);
    ++passes_;
    pass_done_.notify_all();
    wake_.wait_until(lock, stop, next, [this] { return refresh_now_; });
  }
}

}  // namespace bot_shield
