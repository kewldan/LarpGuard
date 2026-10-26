#include "score/rule_samples.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <utility>

#include "score/rules.h"

namespace bot_shield {

RuleContext LiveRuleSample::View() const {
  RuleContext context;
  context.request = &request;
  context.ip = ip;
  context.host = host;
  context.path = path;
  context.query = query;
  context.sni = sni;
  context.alpn = alpn;
  context.ja4 = ja4;
  context.h2_fingerprint = h2_fingerprint;
  context.pseudo_order = pseudo_order;
  context.header_fp = header_fp;
  context.tcp_fingerprint = tcp_fingerprint;
  context.ua_family = ua_family;
  context.ua_engine = ua_engine;
  context.ua_os = ua_os;
  context.ua_tool = ua_tool;
  context.score = score;
  context.bot_class = bot_class;
  context.reasons = &reasons;
  context.asn = asn;
  context.asn_org = asn_org;
  context.asn_country = asn_country;
  context.country = country;
  context.asn_hosting = asn_hosting;
  context.signed_agent = signed_agent;
  context.tcp_rtt_ms = tcp_rtt_ms;
  context.handshake_ms = handshake_ms;
  return context;
}

RuleSampleRing::RuleSampleRing(std::size_t capacity)
    : per_shard_((capacity + kShards - 1) / kShards) {
  for (Shard& shard : shards_) shard.ring.reserve(per_shard_);
}

bool RuleSampleRing::WantSample() {
  if (per_shard_ == 0) return false;
  if (stored_.load(std::memory_order_relaxed) < per_shard_ * kShards) {
    return true;
  }
  thread_local uint32_t tick = 0;
  return ++tick % kSampleEvery == 0;
}

void RuleSampleRing::Add(LiveRuleSample sample) {
  if (per_shard_ == 0) return;
  // Round robin, so the shards fill evenly whatever the worker count.
  Shard& shard =
      shards_[next_shard_.fetch_add(1, std::memory_order_relaxed) % kShards];
  const std::scoped_lock lock(shard.mutex);
  if (shard.ring.size() < per_shard_) {
    shard.ring.push_back(std::move(sample));
    stored_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  shard.ring[shard.next] = std::move(sample);
  shard.next = (shard.next + 1) % per_shard_;
}

void RuleSampleRing::ForEach(
    const std::function<void(const LiveRuleSample&)>& visit) const {
  for (const Shard& shard : shards_) {
    const std::scoped_lock lock(shard.mutex);
    for (const LiveRuleSample& sample : shard.ring) visit(sample);
  }
}

std::size_t RuleSampleRing::size() const {
  return stored_.load(std::memory_order_relaxed);
}

}  // namespace bot_shield
