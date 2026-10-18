#ifndef BOT_SHIELD_ADMIN_LISTS_H_
#define BOT_SHIELD_ADMIN_LISTS_H_

#include <asio/ip/address.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/network.h"
#include "score/policy.h"

namespace bot_shield {

// What an operational list entry matches on.
enum class ListKind { kIp, kJa4, kHeaderFp };

std::string_view ListKindName(ListKind kind);

// An allow/block entry added at runtime through the admin API.
struct ListEntry {
  uint64_t id = 0;
  ListKind kind = ListKind::kIp;
  // IP or CIDR (normalized to a network) or a glob for ja4 / header_fp.
  std::string value;
  Action action = Action::kBlock;
  // Host pattern ("shop.test", "*.shop.test"); empty: every host.
  std::string host;
  int64_t created_at = 0;  // Unix seconds.
  int64_t expires_at = 0;  // Unix seconds; 0: never.
  std::string comment;
  Network network;  // For kIp.
};

struct ListMatchInput {
  asio::ip::address ip;
  std::string_view ja4;
  std::string_view header_fp;
  std::string_view host;
  int64_t now = 0;  // Unix seconds.
};

struct ListMatch {
  uint64_t id = 0;
  Action action = Action::kAllow;
};

// Operational allow/block lists: thread-safe, expiring, optionally saved to
// a JSON file so they survive restarts. Matching entries beat rules and the
// verdict's class; when both match, an allow entry wins (explicit trust).
class ListStore {
 public:
  // `state_file` empty: entries live in memory only.
  explicit ListStore(std::string state_file);

  ListStore(const ListStore&) = delete;
  ListStore& operator=(const ListStore&) = delete;

  // Loads the state file (missing file: empty lists).
  bool Load(int64_t now, std::string* error);

  // Validates `entry` (id and created_at are assigned) and stores it.
  bool Add(ListEntry entry, int64_t now, ListEntry* stored, std::string* error);
  bool Remove(uint64_t id, std::string* error);
  std::vector<ListEntry> Entries(int64_t now) const;
  std::optional<ListMatch> Match(const ListMatchInput& input) const;

  static nlohmann::json ToJson(const ListEntry& entry);
  // Parses an entry from the admin API or the state file; `ttl` (seconds or
  // a duration like "1h") sets expires_at relative to `now`.
  static bool FromJson(const nlohmann::json& json, int64_t now,
                       ListEntry* entry, std::string* error);

 private:
  bool SaveLocked(std::string* error) const;

  const std::string state_file_;
  mutable std::mutex mutex_;
  std::vector<ListEntry> entries_;
  uint64_t next_id_ = 1;
  // Lets Match() skip the lock while the lists are empty (the common case).
  std::atomic<std::size_t> count_{0};
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_LISTS_H_
