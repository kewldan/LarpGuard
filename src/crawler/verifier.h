#ifndef BOT_SHIELD_CRAWLER_VERIFIER_H_
#define BOT_SHIELD_CRAWLER_VERIFIER_H_

#include <asio/ip/address.hpp>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "crawler/crawlers.h"

namespace bot_shield {

// Checks that a request claiming a search crawler comes from it: the
// address's reverse DNS name is in the crawler's domains and resolves back
// to the address. Lookups run on background threads; the request path only
// reads the cache, so the first request of a new address is "pending".
class CrawlerVerifier {
 public:
  struct Resolver {
    // PTR name of an address; "" when there is none.
    std::function<std::string(const asio::ip::address&)> reverse;
    // Addresses of a name; empty on failure.
    std::function<std::vector<asio::ip::address>(const std::string&)> forward;
  };
  // getnameinfo / getaddrinfo (the system resolver and its timeouts).
  static Resolver SystemResolver();

  struct Settings {
    std::chrono::seconds verified_ttl{std::chrono::hours(24)};
    std::chrono::seconds failed_ttl{std::chrono::hours(1)};
    std::size_t max_entries = 100000;
    std::size_t max_queue = 1024;
    int threads = 2;
  };

  CrawlerVerifier(Resolver resolver, Settings settings);
  ~CrawlerVerifier();
  CrawlerVerifier(const CrawlerVerifier&) = delete;
  CrawlerVerifier& operator=(const CrawlerVerifier&) = delete;

  // Cached result for `crawler` at `ip`; on a miss, queues a lookup and
  // returns kPending. `now` in Unix seconds. `why` (optional) gets how the
  // lookup went, without the PTR name (it may carry the address):
  // "verified:<domain>", "no_ptr", "outside_domains", "forward_mismatch",
  // or "queued" while pending.
  CrawlerStatus Check(const KnownCrawler& crawler,
                      const asio::ip::address& peer, int64_t now,
                      std::string* why = nullptr);

  // Blocks until no lookup is queued or running (tests).
  void WaitIdle();

 private:
  struct Job {
    const KnownCrawler* crawler = nullptr;
    asio::ip::address ip;
    std::string key;
    int64_t queued = 0;  // Unix seconds; results expire from here.
  };
  struct Entry {
    CrawlerStatus status;
    int64_t expires;
    std::string why;
  };

  void Run(const std::stop_token& stop);
  // True when verified; `why` as in Check().
  bool Verify(const KnownCrawler& crawler, const asio::ip::address& ip,
              std::string* why) const;

  Resolver resolver_;
  Settings settings_;
  std::mutex mutex_;
  std::condition_variable_any wake_;
  std::condition_variable_any idle_;
  std::deque<Job> queue_;
  std::set<std::string, std::less<>> in_flight_;
  std::map<std::string, Entry, std::less<>> cache_;
  int running_ = 0;
  std::vector<std::jthread> threads_;  // Last: joined first.
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_CRAWLER_VERIFIER_H_
