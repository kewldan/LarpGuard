#include "crawler/verifier.h"

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>  // IWYU pragma: keep (socklen_t on Linux)

#include <array>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/ip/tcp.hpp>
#include <cstdint>
#include <cstring>
#include <format>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "common/metrics.h"
#include "crawler/crawlers.h"

namespace bot_shield {
namespace {

asio::ip::address Normalize(const asio::ip::address& ip) {
  if (ip.is_v6() && ip.to_v6().is_v4_mapped()) {
    return asio::ip::make_address_v4(asio::ip::v4_mapped, ip.to_v6());
  }
  return ip;
}

}  // namespace

CrawlerVerifier::Resolver CrawlerVerifier::SystemResolver() {
  Resolver resolver;
  resolver.reverse = [](const asio::ip::address& ip) -> std::string {
    const asio::ip::tcp::endpoint endpoint(ip, 0);
    std::array<char, NI_MAXHOST> host{};
    if (getnameinfo(endpoint.data(), static_cast<socklen_t>(endpoint.size()),
                    host.data(), host.size(), nullptr, 0, NI_NAMEREQD) != 0) {
      return {};
    }
    return host.data();
  };
  resolver.forward =
      [](const std::string& name) -> std::vector<asio::ip::address> {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    std::vector<asio::ip::address> out;
    if (getaddrinfo(name.c_str(), nullptr, &hints, &result) != 0) return out;
    for (const addrinfo* it = result; it != nullptr; it = it->ai_next) {
      asio::ip::tcp::endpoint endpoint;
      if (it->ai_addrlen > endpoint.capacity()) continue;
      std::memcpy(endpoint.data(), it->ai_addr, it->ai_addrlen);
      endpoint.resize(it->ai_addrlen);
      out.push_back(endpoint.address());
    }
    freeaddrinfo(result);
    return out;
  };
  return resolver;
}

CrawlerVerifier::CrawlerVerifier(Resolver resolver, Settings settings)
    : resolver_(std::move(resolver)), settings_(settings) {
  for (int i = 0; i < settings_.threads; ++i) {
    threads_.emplace_back([this](const std::stop_token& stop) { Run(stop); });
  }
}

CrawlerVerifier::~CrawlerVerifier() {
  for (std::jthread& thread : threads_) thread.request_stop();
  wake_.notify_all();
  threads_.clear();
}

CrawlerStatus CrawlerVerifier::Check(const KnownCrawler& crawler,
                                     const asio::ip::address& peer,
                                     int64_t now) {
  const asio::ip::address ip = Normalize(peer);
  std::string key = std::format("{}|{}", crawler.id, ip.to_string());
  const std::scoped_lock lock(mutex_);
  if (const auto it = cache_.find(key); it != cache_.end()) {
    if (it->second.expires > now) return it->second.status;
    cache_.erase(it);
  }
  if (in_flight_.contains(key)) return CrawlerStatus::kPending;
  if (queue_.size() >= settings_.max_queue) {
    GlobalMetrics().crawler_lookups_dropped.Inc();
    return CrawlerStatus::kPending;
  }
  in_flight_.insert(key);
  queue_.push_back({&crawler, ip, std::move(key), now});
  wake_.notify_one();
  return CrawlerStatus::kPending;
}

void CrawlerVerifier::WaitIdle() {
  std::unique_lock lock(mutex_);
  idle_.wait(lock, [this] { return queue_.empty() && running_ == 0; });
}

void CrawlerVerifier::Run(const std::stop_token& stop) {
  while (true) {
    Job job;
    {
      std::unique_lock lock(mutex_);
      if (!wake_.wait(lock, stop, [this] { return !queue_.empty(); })) {
        return;
      }
      job = std::move(queue_.front());
      queue_.pop_front();
      ++running_;
    }
    const bool verified = Verify(*job.crawler, job.ip);
    (verified ? GlobalMetrics().crawlers_verified
              : GlobalMetrics().crawlers_failed)
        .Inc();
    const int64_t ttl =
        (verified ? settings_.verified_ttl : settings_.failed_ttl).count();
    const std::scoped_lock lock(mutex_);
    // Bounded memory: drop the cache when it is full (rare; it refills).
    if (cache_.size() >= settings_.max_entries) cache_.clear();
    cache_[job.key] = {
        verified ? CrawlerStatus::kVerified : CrawlerStatus::kFailed,
        job.queued + ttl};
    in_flight_.erase(job.key);
    --running_;
    if (queue_.empty() && running_ == 0) idle_.notify_all();
  }
}

bool CrawlerVerifier::Verify(const KnownCrawler& crawler,
                             const asio::ip::address& ip) const {
  const std::string name = resolver_.reverse(ip);
  if (name.empty() || !HostnameInDomains(name, crawler.domains)) return false;
  for (const asio::ip::address& address : resolver_.forward(name)) {
    if (Normalize(address) == ip) return true;
  }
  return false;
}

}  // namespace bot_shield
