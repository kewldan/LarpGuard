#ifndef BOT_SHIELD_COMMON_REFRESHER_H_
#define BOT_SHIELD_COMMON_REFRESHER_H_

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace bot_shield {

// A dataset downloaded in the background: crawler IP ranges, the ASN
// database. Kept in `cache_file` so a restart (or a host without network)
// starts with the last good copy.
struct RefreshSource {
  std::string name;  // For logs.
  std::string url;
  std::string cache_file;  // "" = memory only.
  std::chrono::seconds refresh{std::chrono::hours(24)};
  std::chrono::seconds retry{std::chrono::minutes(10)};
  std::size_t max_size = std::size_t{64} << 20;
  // Parses and publishes the data; false (with a reason) keeps what is
  // there. Runs on the refresher thread.
  std::function<bool(std::string_view data, std::string* error)> apply;
  // Download function; HttpFetch by default (tests replace it).
  std::function<bool(const std::string& url, std::size_t max_size,
                     std::string* data, std::string* error)>
      fetch;
};

// One background thread for every source: load the cache at start, then
// download each source when it is due. Downloads never touch worker loops.
class DataRefresher {
 public:
  explicit DataRefresher(std::vector<RefreshSource> sources);
  ~DataRefresher();
  DataRefresher(const DataRefresher&) = delete;
  DataRefresher& operator=(const DataRefresher&) = delete;

  // Runs the first pass (caches, then due downloads) on the thread.
  void Start();
  // Downloads everything now (tests, admin).
  void RefreshNow();
  // Blocks until a full pass over the sources has finished (tests).
  void WaitForPass(int passes);

 private:
  struct State {
    RefreshSource source;
    std::chrono::system_clock::time_point due;
  };

  void Run(const std::stop_token& stop);
  void LoadCache(State* state);
  void Download(State* state);

  std::mutex mutex_;
  std::condition_variable_any wake_;
  std::condition_variable_any pass_done_;
  std::vector<State> states_;
  bool refresh_now_ = false;
  int passes_ = 0;
  std::jthread thread_;  // Last: joined first.
};

// Default `fetch`: HTTP GET with HttpFetch, 200 only.
bool FetchUrl(const std::string& url, std::size_t max_size, std::string* data,
              std::string* error);

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_REFRESHER_H_
