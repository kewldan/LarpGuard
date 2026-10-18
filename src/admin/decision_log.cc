#include "admin/decision_log.h"

#include <cstddef>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <ranges>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield {

nlohmann::json DecisionToJson(const DecisionRecord& record) {
  nlohmann::json json = {
      {"request_id", record.request_id},
      {"time_ms", record.time_ms},
      {"host", record.host},
      {"method", record.method},
      {"path_group", record.path_group},
      {"ip", record.ip},
      {"user_agent", record.user_agent},
      {"ja4", record.ja4},
      {"h2_fp", record.h2_fingerprint},
      {"header_fp", record.header_fp},
      {"mode", record.mode},
      {"score", record.score},
      {"class", record.bot_class},
      {"reasons", record.reasons},
      {"action", record.action},
      {"would_action", record.would_action},
      {"status", record.status},
      {"local", record.local},
      {"duration_ms", record.duration_ms},
  };
  if (!record.rate_limit.empty()) json["rate_limit"] = record.rate_limit;
  return json;
}

void DecisionLog::Add(DecisionRecord record) {
  if (capacity_ == 0) return;
  std::scoped_lock lock(mutex_);
  if (records_.size() >= capacity_) records_.pop_front();
  records_.push_back(std::move(record));
}

std::optional<DecisionRecord> DecisionLog::Find(
    std::string_view request_id) const {
  std::scoped_lock lock(mutex_);
  for (const DecisionRecord& record : std::views::reverse(records_)) {
    if (record.request_id == request_id) return record;
  }
  return std::nullopt;
}

std::vector<DecisionRecord> DecisionLog::Recent(
    std::size_t limit, std::string_view host,
    std::string_view bot_class) const {
  std::scoped_lock lock(mutex_);
  std::vector<DecisionRecord> out;
  for (const DecisionRecord& record : std::views::reverse(records_)) {
    if (out.size() >= limit) break;
    if (!host.empty() && record.host != host) continue;
    if (!bot_class.empty() && record.bot_class != bot_class) continue;
    out.push_back(record);
  }
  return out;
}

}  // namespace bot_shield
