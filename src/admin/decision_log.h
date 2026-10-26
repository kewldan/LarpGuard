#ifndef BOT_SHIELD_ADMIN_DECISION_LOG_H_
#define BOT_SHIELD_ADMIN_DECISION_LOG_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {

// One proxied request and what was decided about it.
struct DecisionRecord {
  std::string request_id;
  int64_t time_ms = 0;  // Unix milliseconds.
  std::string host;
  std::string method;
  std::string path_group;
  // Full address: this log stays in memory on the gateway (unlike events)
  // and exists so an operator can act on it.
  std::string ip;
  std::string user_agent;
  std::string ja4;
  std::string h2_fingerprint;
  std::string header_fp;
  std::string mode;
  int score = -1;
  std::string bot_class;
  std::vector<std::string> reasons;
  std::string action;
  std::string would_action;
  std::string rate_limit;
  int status = 0;
  bool local = false;
  int64_t duration_ms = 0;
  // Steps of the crawler / signed agent check (Exchange::crawler_check).
  std::vector<std::string> crawler_check;
};

nlohmann::json DecisionToJson(const DecisionRecord& record);

// The last N decisions, for GET /decisions without ClickHouse.
class DecisionLog {
 public:
  explicit DecisionLog(std::size_t capacity) : capacity_(capacity) {}

  DecisionLog(const DecisionLog&) = delete;
  DecisionLog& operator=(const DecisionLog&) = delete;

  void Add(DecisionRecord record);
  std::optional<DecisionRecord> Find(std::string_view request_id) const;
  // Newest first; empty filters match everything.
  std::vector<DecisionRecord> Recent(std::size_t limit, std::string_view host,
                                     std::string_view bot_class) const;

 private:
  const std::size_t capacity_;
  mutable std::mutex mutex_;
  std::deque<DecisionRecord> records_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_DECISION_LOG_H_
