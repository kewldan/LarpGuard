#include "docker/labels.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/host.h"
#include "docker/client.h"
#include "ratelimit/limits.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

constexpr std::string_view kPrefix = "botshield.";
constexpr std::string_view kRateLimitPrefix = "botshield.ratelimit.";

std::vector<std::string> SplitList(std::string_view text) {
  std::vector<std::string> out;
  while (!text.empty()) {
    const std::size_t comma = text.find(',');
    std::string_view item = text.substr(0, comma);
    while (!item.empty() && item.front() == ' ') item.remove_prefix(1);
    while (!item.empty() && item.back() == ' ') item.remove_suffix(1);
    if (!item.empty()) out.emplace_back(item);
    if (comma == std::string_view::npos) break;
    text.remove_prefix(comma + 1);
  }
  return out;
}

bool IsValidPattern(const std::string& host) {
  return IsValidHostName(host.starts_with("*.")
                             ? std::string_view(host).substr(2)
                             : std::string_view(host));
}

// Hosts a container serves: botshield.hosts, else its Traefik HTTP routers.
std::vector<std::string> ContainerHosts(const ContainerInfo& container) {
  std::vector<std::string> hosts;
  if (const auto it = container.labels.find("botshield.hosts");
      it != container.labels.end()) {
    hosts = SplitList(it->second);
  } else {
    for (const auto& [key, value] : container.labels) {
      if (key.starts_with("traefik.http.routers.") && key.ends_with(".rule")) {
        for (std::string& host : TraefikRuleHosts(value)) {
          hosts.push_back(std::move(host));
        }
      }
    }
  }
  for (std::string& host : hosts) host = NormalizeHost(host);
  std::ranges::sort(hosts);
  hosts.erase(std::ranges::unique(hosts).begin(), hosts.end());
  return hosts;
}

}  // namespace

std::vector<std::string> TraefikRuleHosts(std::string_view rule) {
  std::vector<std::string> hosts;
  std::size_t pos = 0;
  while ((pos = rule.find("Host(", pos)) != std::string_view::npos) {
    // Skip HostRegexp(, HostSNI( etc.: "Host(" must not follow a letter.
    if (pos > 0 && std::isalpha(static_cast<unsigned char>(rule[pos - 1]))) {
      pos += 5;
      continue;
    }
    const std::size_t open = pos + 5;
    const std::size_t close = rule.find(')', open);
    if (close == std::string_view::npos) break;
    for (std::string argument : SplitList(rule.substr(open, close - open))) {
      if (argument.size() >= 2 &&
          (argument.front() == '`' || argument.front() == '"' ||
           argument.front() == '\'') &&
          argument.back() == argument.front()) {
        hosts.push_back(argument.substr(1, argument.size() - 2));
      }
    }
    pos = close;
  }
  return hosts;
}

bool ParseRateLimitLabel(std::string_view value, RateLimitSpec* spec,
                         std::string* error) {
  bool has_rate = false;
  bool has_burst = false;
  while (!value.empty()) {
    while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
    const std::size_t end = value.find(' ');
    const std::string_view token = value.substr(0, end);
    value = end == std::string_view::npos ? std::string_view()
                                          : value.substr(end + 1);
    if (token.empty()) continue;
    const std::size_t equals = token.find('=');
    if (equals == std::string_view::npos) {
      *error = std::format("expected key=value, got '{}'", token);
      return false;
    }
    const std::string_view key = token.substr(0, equals);
    const std::string_view text = token.substr(equals + 1);
    if (key == "rate") {
      if (!ParseRate(text, &spec->count, &spec->period)) {
        *error = std::format("bad rate '{}'", text);
        return false;
      }
      has_rate = true;
    } else if (key == "burst") {
      spec->burst = 0;
      for (const char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
          *error = std::format("bad burst '{}'", text);
          return false;
        }
        spec->burst = spec->burst * 10 + (c - '0');
      }
      has_burst = true;
    } else if (key == "key") {
      spec->key = SplitList(text);
    } else if (key == "path" || key == "paths") {
      spec->paths = SplitList(text);
    } else if (key == "methods") {
      spec->methods = SplitList(text);
    } else if (key == "classes") {
      spec->classes = SplitList(text);
    } else {
      *error = std::format("unknown setting '{}'", key);
      return false;
    }
  }
  if (!has_rate) {
    *error = "rate=<n>/<s|m|h|d> is required";
    return false;
  }
  if (!has_burst) spec->burst = spec->count;
  if (spec->key.empty()) spec->key = {"ip"};
  return true;
}

std::shared_ptr<const LabelPolicies> LabelPolicies::Build(
    const std::vector<ContainerInfo>& containers,
    std::vector<std::string>* warnings) {
  auto policies = std::make_shared<LabelPolicies>();
  // Deterministic conflict resolution: containers by name.
  std::vector<const ContainerInfo*> sorted;
  sorted.reserve(containers.size());
  for (const ContainerInfo& container : containers) {
    sorted.push_back(&container);
  }
  std::ranges::sort(sorted, {}, &ContainerInfo::name);

  std::map<std::string, std::string> owners;  // host -> container
  std::vector<RateLimitSpec> limits;
  for (const ContainerInfo* container : sorted) {
    bool uses_labels = false;
    for (const auto& [key, value] : container->labels) {
      if (key.starts_with(kPrefix) && key != "botshield.hosts") {
        uses_labels = true;
        break;
      }
    }
    if (!uses_labels) continue;
    const auto warn = [&](std::string_view message) {
      warnings->push_back(
          std::format("container {}: {}", container->name, message));
    };

    const std::vector<std::string> hosts = ContainerHosts(*container);
    if (hosts.empty()) {
      warn("botshield.* labels but no hosts (set botshield.hosts)");
      continue;
    }
    std::optional<HostMode> mode;
    if (const auto it = container->labels.find("botshield.mode");
        it != container->labels.end()) {
      HostMode parsed = HostMode::kShadow;
      if (ParseHostMode(it->second, &parsed)) {
        mode = parsed;
      } else {
        warn(std::format("botshield.mode '{}' is not shadow, enforce or off",
                         it->second));
      }
    }
    bool passthrough = false;
    if (const auto it = container->labels.find("botshield.passthrough");
        it != container->labels.end()) {
      passthrough = it->second == "true";
      if (it->second != "true" && it->second != "false") {
        warn("botshield.passthrough must be true or false");
      }
    }

    bool ai_crawlers_set = false;
    std::optional<Action> ai_crawlers;
    if (const auto it = container->labels.find("botshield.ai_crawlers");
        it != container->labels.end()) {
      Action action = Action::kAllow;
      if (it->second == "default") {
        ai_crawlers_set = true;
      } else if (ParseAction(it->second, &action)) {
        ai_crawlers_set = true;
        ai_crawlers = action;
      } else {
        warn(
            std::format("botshield.ai_crawlers '{}' is not an action or "
                        "default",
                        it->second));
      }
    }
    // Comma-separated globs on the path; each must start with '/'.
    const auto paths = [&](std::string_view label) {
      std::vector<std::string> out;
      if (const auto it = container->labels.find(std::string(label));
          it != container->labels.end()) {
        for (std::string& path : SplitList(it->second)) {
          if (path.starts_with('/')) {
            out.push_back(std::move(path));
          } else {
            warn(std::format("{}: '{}' must start with /", label, path));
          }
        }
      }
      return out;
    };
    const std::vector<std::string> challenge_paths =
        paths("botshield.challenge.paths");
    const std::vector<std::string> honeypot_paths =
        paths("botshield.honeypot.paths");

    std::vector<std::string> owned_hosts;
    for (const std::string& host : hosts) {
      if (!IsValidPattern(host)) {
        warn(std::format("invalid host '{}'", host));
        continue;
      }
      const auto [it, inserted] = owners.emplace(host, container->name);
      if (!inserted) {
        warn(std::format("host {} is already configured by container {}", host,
                         it->second));
        continue;
      }
      owned_hosts.push_back(host);
      policies->hosts_.push_back(LabelHostPolicy{
          host, container->name, mode, passthrough, ai_crawlers_set,
          ai_crawlers, challenge_paths, honeypot_paths});
    }

    for (const auto& [key, value] : container->labels) {
      if (!key.starts_with(kRateLimitPrefix)) continue;
      const std::string name = key.substr(kRateLimitPrefix.size());
      RateLimitSpec spec;
      std::string error;
      if (name.empty() || !ParseRateLimitLabel(value, &spec, &error)) {
        warn(std::format("{}: {}", key, error.empty() ? "empty name" : error));
        continue;
      }
      spec.name = std::format("{}/{}", container->name, name);
      spec.hosts = owned_hosts;
      // Validate alone so one bad limit does not drop the others.
      RateLimitSet single;
      if (!RateLimitSet::Compile({spec}, &single, &error)) {
        warn(error);
        continue;
      }
      if (!owned_hosts.empty()) limits.push_back(std::move(spec));
    }
  }
  std::string error;
  if (!RateLimitSet::Compile(limits, &policies->rate_limits_, &error)) {
    warnings->push_back(error);
    limits.clear();
  }
  policies->rate_limit_count_ = limits.size();
  return policies;
}

const LabelHostPolicy* LabelPolicies::Find(std::string_view host) const {
  for (const LabelHostPolicy& policy : hosts_) {
    if (policy.host == host) return &policy;
  }
  for (const LabelHostPolicy& policy : hosts_) {
    if (policy.host.starts_with("*.") && HostMatches(policy.host, host)) {
      return &policy;
    }
  }
  return nullptr;
}

std::optional<HostMode> LabelPolicies::ModeFor(std::string_view host) const {
  const LabelHostPolicy* policy = Find(host);
  return policy == nullptr ? std::nullopt : policy->mode;
}

bool LabelPolicies::IsPassthrough(std::string_view host) const {
  const LabelHostPolicy* policy = Find(host);
  return policy != nullptr && policy->passthrough;
}

LabelStore::LabelStore() : snapshot_(std::make_shared<LabelPolicies>()) {}

std::shared_ptr<const LabelPolicies> LabelStore::snapshot() const {
  std::scoped_lock lock(mutex_);
  return snapshot_;
}

void LabelStore::set_snapshot(std::shared_ptr<const LabelPolicies> snapshot) {
  std::scoped_lock lock(mutex_);
  snapshot_ = std::move(snapshot);
}

}  // namespace bot_shield
