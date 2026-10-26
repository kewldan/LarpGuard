#ifndef BOT_SHIELD_SCORE_RULE_SAMPLES_H_
#define BOT_SHIELD_SCORE_RULE_SAMPLES_H_

#include <array>
#include <asio/ip/address.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "fp/http_request.h"
#include "score/rules.h"

namespace bot_shield {

// A request as rules saw it, owning everything a RuleContext points to,
// with what was decided.
struct LiveRuleSample {
  // A RuleContext over the fields below (valid while the sample lives).
  RuleContext View() const;

  int64_t time_ms = 0;  // Unix milliseconds.
  std::string request_id;
  std::string action;
  std::string would_action;

  HttpRequest request;
  asio::ip::address ip;
  std::string host, path, query, sni, alpn, ja4, h2_fingerprint, pseudo_order,
      header_fp, tcp_fingerprint, ua_family, ua_engine, ua_os, ua_tool,
      bot_class, asn_org, asn_country, country, signed_agent;
  std::vector<std::string> reasons;
  int64_t score = 0;
  int64_t asn = 0;
  bool asn_hosting = false;
  int64_t tcp_rtt_ms = -1;
  int64_t handshake_ms = -1;
};

// Recent requests with all a rule can read (headers, cookies, query, the
// full address, the exact path), for testing a draft rule on live traffic
// (POST /rules/test with "live": true). Events lack these by design (10.3),
// so this stays in the gateway's memory, like the decision log: the admin
// API answers with matches described by event fields only. Shared by the
// workers: sharded rings; every request until a ring is full, then every
// kSampleEvery-th per thread.
class RuleSampleRing {
 public:
  static constexpr std::size_t kShards = 8;
  static constexpr uint32_t kSampleEvery = 8;

  // `capacity` over all shards; 0 keeps nothing.
  explicit RuleSampleRing(std::size_t capacity);

  RuleSampleRing(const RuleSampleRing&) = delete;
  RuleSampleRing& operator=(const RuleSampleRing&) = delete;

  // Whether to keep the next request of this thread (cheap; call first,
  // then build the sample only when true).
  bool WantSample();
  void Add(LiveRuleSample sample);

  // Calls `visit` on every sample, one shard locked at a time.
  void ForEach(const std::function<void(const LiveRuleSample&)>& visit) const;
  std::size_t size() const;

 private:
  struct Shard {
    mutable std::mutex mutex;
    std::vector<LiveRuleSample> ring;
    std::size_t next = 0;
  };

  const std::size_t per_shard_;
  std::atomic<std::size_t> stored_{0};
  std::atomic<std::size_t> next_shard_{0};
  std::array<Shard, kShards> shards_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SCORE_RULE_SAMPLES_H_
