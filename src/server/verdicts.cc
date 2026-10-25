#include "server/verdicts.h"

#include <chrono>
#include <format>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "config/config.h"
#include "fp/library.h"
#include "model/gbdt.h"
#include "ratelimit/limits.h"
#include "score/policy.h"
#include "score/rules.h"
#include "score/scorer.h"

namespace bot_shield {

bool VerdictSet::Build(const Config& config,
                       std::shared_ptr<const VerdictSet>* out,
                       std::string* error) {
  auto set = std::make_shared<VerdictSet>();
  auto library =
      std::make_shared<FingerprintLibrary>(FingerprintLibrary::BuiltIn());
  if (!config.fingerprint_library.empty() &&
      !FingerprintLibrary::Load(config.fingerprint_library, library.get(),
                                error)) {
    *error = std::format("fingerprints: {}", *error);
    return false;
  }
  set->library = std::move(library);
  set->scorer = std::make_shared<const Scorer>(
      set->library.get(), config.policy.suspicious_threshold,
      config.policy.bot_threshold);
  set->policy = std::make_shared<const Policy>(config.policy);
  if (!RuleSet::Compile(config.rules, &set->rules, error) ||
      !RateLimitSet::Compile(config.rate_limits, &set->rate_limits, error)) {
    return false;
  }
  if (config.throttle) {
    RateLimitSpec spec = *config.throttle;
    spec.name = "throttle";
    if (!RateLimitSet::Compile({spec}, &set->throttle, error)) {
      *error = std::format("throttle: {}", *error);
      return false;
    }
  }
  set->honeypot_paths = config.honeypot_paths;
  set->ai_crawler_action = config.crawlers_ai;
  set->ai_robots = config.crawlers_ai_robots;
  set->trusted_agents = config.web_bot_auth_trusted;
  set->model_threshold = config.model_threshold;
  if (!config.model_file.empty()) {
    auto model = std::make_shared<GbdtModel>();
    if (!GbdtModel::Load(config.model_file, model.get(), error)) {
      *error = std::format("model: {}", *error);
      return false;
    }
    set->model = std::move(model);
  }
  set->config = std::make_shared<const Config>(config);
  set->built_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  *out = std::move(set);
  return true;
}

std::shared_ptr<const VerdictSet> WithConsoleModes(
    const VerdictSet& verdicts,
    std::vector<std::pair<std::string, HostMode>> console_modes) {
  auto copy = std::make_shared<VerdictSet>(verdicts);
  PolicySettings settings = verdicts.policy->settings();
  settings.console_modes = std::move(console_modes);
  copy->policy = std::make_shared<const Policy>(std::move(settings));
  return copy;
}

std::shared_ptr<const VerdictSet> VerdictStore::snapshot() const {
  const std::scoped_lock lock(mutex_);
  return current_;
}

void VerdictStore::set(const std::shared_ptr<const VerdictSet>& verdicts) {
  auto copy = std::make_shared<VerdictSet>();
  // Shallow fields are cheap to copy; the generation is stamped here.
  *copy = *verdicts;
  const std::scoped_lock lock(mutex_);
  copy->generation = ++generation_;
  current_ = std::move(copy);
}

}  // namespace bot_shield
