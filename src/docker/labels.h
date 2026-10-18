#ifndef BOT_SHIELD_DOCKER_LABELS_H_
#define BOT_SHIELD_DOCKER_LABELS_H_

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "docker/client.h"
#include "ratelimit/limits.h"
#include "score/policy.h"

namespace bot_shield {

// Policies declared with docker labels:
//   botshield.hosts=a.example.com,b.example.com   (default: Traefik Host())
//   botshield.mode=shadow|enforce|off
//   botshield.passthrough=true
//   botshield.ratelimit.<name>=rate=20/s burst=40 key=ip path=/api/*
//                              methods=POST classes=bot
struct LabelHostPolicy {
  std::string host;
  std::string container;
  std::optional<HostMode> mode;
  bool passthrough = false;
};

class LabelPolicies {
 public:
  // Builds policies from running containers. Problems with one container
  // are reported in `warnings` and skip only that part.
  static std::shared_ptr<const LabelPolicies> Build(
      const std::vector<ContainerInfo>& containers,
      std::vector<std::string>* warnings);

  // Exact host first, then "*.parent" entries.
  std::optional<HostMode> ModeFor(std::string_view host) const;
  bool IsPassthrough(std::string_view host) const;
  const RateLimitSet& rate_limits() const { return rate_limits_; }

  std::size_t host_count() const { return hosts_.size(); }
  std::size_t rate_limit_count() const { return rate_limit_count_; }
  const std::vector<LabelHostPolicy>& hosts() const { return hosts_; }

 private:
  const LabelHostPolicy* Find(std::string_view host) const;

  std::vector<LabelHostPolicy> hosts_;
  RateLimitSet rate_limits_;
  std::size_t rate_limit_count_ = 0;
};

// Host names from a Traefik router rule: Host(`a`) || Host(`b`, `c`).
std::vector<std::string> TraefikRuleHosts(std::string_view rule);

// Parses a botshield.ratelimit.* value into `spec` (name and hosts are set
// by the caller).
bool ParseRateLimitLabel(std::string_view value, RateLimitSpec* spec,
                         std::string* error);

// The current label policies, swapped as a whole by the watcher.
class LabelStore {
 public:
  LabelStore();

  std::shared_ptr<const LabelPolicies> snapshot() const;
  void set_snapshot(std::shared_ptr<const LabelPolicies> snapshot);

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<const LabelPolicies> snapshot_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_DOCKER_LABELS_H_
