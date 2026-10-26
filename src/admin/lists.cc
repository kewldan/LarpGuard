#include "admin/lists.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/host.h"
#include "common/network.h"
#include "config/config.h"
#include "fp/library.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

bool ParseKind(std::string_view text, ListKind* kind) {
  if (text == "ip") {
    *kind = ListKind::kIp;
  } else if (text == "ja4") {
    *kind = ListKind::kJa4;
  } else if (text == "header_fp") {
    *kind = ListKind::kHeaderFp;
  } else if (text == "asn") {
    *kind = ListKind::kAsn;
  } else {
    return false;
  }
  return true;
}

bool EntryMatches(const ListEntry& entry, const ListMatchInput& input) {
  if (entry.expires_at != 0 && entry.expires_at <= input.now) return false;
  if (!entry.host.empty() && !HostMatches(entry.host, input.host)) {
    return false;
  }
  switch (entry.kind) {
    case ListKind::kIp:
      return entry.network.Contains(input.ip);
    case ListKind::kJa4:
      return !input.ja4.empty() && GlobMatch(entry.value, input.ja4);
    case ListKind::kHeaderFp:
      return !input.header_fp.empty() &&
             GlobMatch(entry.value, input.header_fp);
    case ListKind::kAsn:
      return input.asn != 0 && entry.asn == input.asn;
  }
  return false;
}

// "64500", "AS64500" or "as64500".
bool ParseAsn(std::string_view text, uint32_t* asn) {
  if (text.size() > 2 && (text[0] == 'A' || text[0] == 'a') &&
      (text[1] == 'S' || text[1] == 's')) {
    text.remove_prefix(2);
  }
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* begin = text.data();
  const char* end = begin + text.size();
  const auto [ptr, ec] = std::from_chars(begin, end, *asn);
  return !text.empty() && ec == std::errc() && ptr == end && *asn != 0;
}

// Seconds from a "ttl" field: an integer or a duration like "1h".
bool ParseTtl(const nlohmann::json& ttl, int64_t* seconds, std::string* error) {
  *seconds = 0;
  if (ttl.is_number_integer()) {
    *seconds = ttl.get<int64_t>();
  } else if (ttl.is_string()) {
    std::chrono::milliseconds duration{0};
    if (!ParseDuration(ttl.get<std::string>(), &duration)) {
      *error = "ttl must be seconds or a duration like 1h";
      return false;
    }
    *seconds =
        std::chrono::duration_cast<std::chrono::seconds>(duration).count();
  }
  if (*seconds <= 0) {
    *error = "ttl must be positive";
    return false;
  }
  return true;
}

}  // namespace

std::string_view ListKindName(ListKind kind) {
  switch (kind) {
    case ListKind::kIp:
      return "ip";
    case ListKind::kJa4:
      return "ja4";
    case ListKind::kHeaderFp:
      return "header_fp";
    case ListKind::kAsn:
      return "asn";
  }
  return "?";
}

ListStore::ListStore(std::string state_file)
    : state_file_(std::move(state_file)) {}

nlohmann::json ListStore::ToJson(const ListEntry& entry) {
  nlohmann::json json = {
      {"id", entry.id},
      {"kind", ListKindName(entry.kind)},
      {"value", entry.value},
      {"action", ActionName(entry.action)},
      {"created_at", entry.created_at},
      {"expires_at", entry.expires_at},
  };
  if (!entry.host.empty()) json["host"] = entry.host;
  if (!entry.comment.empty()) json["comment"] = entry.comment;
  return json;
}

bool ListStore::FromJson(const nlohmann::json& json, int64_t now,
                         ListEntry* entry, std::string* error) {
  if (!json.is_object()) {
    *error = "expected a JSON object";
    return false;
  }
  const auto string_field = [&](const char* name) -> std::string {
    const auto it = json.find(name);
    return it != json.end() && it->is_string() ? it->get<std::string>()
                                               : std::string();
  };
  ListEntry out;
  if (!ParseKind(string_field("kind"), &out.kind)) {
    *error = "kind must be ip, ja4, header_fp or asn";
    return false;
  }
  out.value = string_field("value");
  if (out.value.empty()) {
    *error = "value is required";
    return false;
  }
  if (out.kind == ListKind::kIp) {
    if (!Network::Parse(out.value, &out.network)) {
      *error = std::format("'{}' is not an IP address or CIDR", out.value);
      return false;
    }
    out.value = out.network.ToString();
  } else if (out.kind == ListKind::kAsn) {
    if (!ParseAsn(out.value, &out.asn)) {
      *error = std::format("'{}' is not an AS number", out.value);
      return false;
    }
    out.value = std::to_string(out.asn);
  }
  if (!ParseAction(string_field("action"), &out.action) ||
      (out.action != Action::kAllow && out.action != Action::kBlock)) {
    *error = "action must be allow or block";
    return false;
  }
  out.host = NormalizeHost(string_field("host"));
  if (!out.host.empty() &&
      !IsValidHostName(out.host.starts_with("*.")
                           ? std::string_view(out.host).substr(2)
                           : std::string_view(out.host))) {
    *error = std::format("invalid host '{}'", out.host);
    return false;
  }
  out.comment = string_field("comment");
  if (const auto it = json.find("id"); it != json.end() && it->is_number()) {
    out.id = it->get<uint64_t>();
  }
  if (const auto it = json.find("created_at");
      it != json.end() && it->is_number()) {
    out.created_at = it->get<int64_t>();
  }
  if (const auto it = json.find("expires_at");
      it != json.end() && it->is_number()) {
    out.expires_at = it->get<int64_t>();
  }
  if (const auto it = json.find("ttl"); it != json.end()) {
    int64_t seconds = 0;
    if (!ParseTtl(*it, &seconds, error)) return false;
    out.expires_at = now + seconds;
  }
  *entry = std::move(out);
  return true;
}

bool ListStore::Load(int64_t now, std::string* error) {
  if (state_file_.empty()) return true;
  std::ifstream file(state_file_);
  if (!file) return true;  // First start.
  std::stringstream contents;
  contents << file.rdbuf();
  const nlohmann::json root =
      nlohmann::json::parse(contents.str(), nullptr, false);
  if (root.is_discarded() || !root.is_array()) {
    *error = std::format("{}: not a JSON array", state_file_);
    return false;
  }
  std::scoped_lock lock(mutex_);
  entries_.clear();
  for (const nlohmann::json& item : root) {
    ListEntry entry;
    std::string entry_error;
    if (!FromJson(item, now, &entry, &entry_error)) {
      *error = std::format("{}: {}", state_file_, entry_error);
      return false;
    }
    next_id_ = std::max(next_id_, entry.id + 1);
    if (entry.expires_at == 0 || entry.expires_at > now) {
      entries_.push_back(std::move(entry));
    }
  }
  count_ = entries_.size();
  return true;
}

bool ListStore::SaveLocked(std::string* error) const {
  if (state_file_.empty()) return true;
  nlohmann::json root = nlohmann::json::array();
  for (const ListEntry& entry : entries_) root.push_back(ToJson(entry));
  const std::string temporary = state_file_ + ".tmp";
  {
    std::ofstream file(temporary, std::ios::trunc);
    file << root.dump(2) << "\n";
    if (!file) {
      *error = std::format("cannot write {}", temporary);
      return false;
    }
  }
  std::error_code ec;
  std::filesystem::rename(temporary, state_file_, ec);
  if (ec) {
    *error = std::format("cannot replace {}: {}", state_file_, ec.message());
    return false;
  }
  return true;
}

bool ListStore::Add(ListEntry entry, int64_t now, ListEntry* stored,
                    std::string* error) {
  std::scoped_lock lock(mutex_);
  std::erase_if(entries_, [now](const ListEntry& existing) {
    return existing.expires_at != 0 && existing.expires_at <= now;
  });
  entry.id = next_id_++;
  entry.created_at = now;
  entries_.push_back(entry);
  if (!SaveLocked(error)) {
    entries_.pop_back();
    count_ = entries_.size();
    return false;
  }
  count_ = entries_.size();
  *stored = std::move(entry);
  return true;
}

bool ListStore::Remove(uint64_t id, std::string* error) {
  std::scoped_lock lock(mutex_);
  const auto it = std::ranges::find(entries_, id, &ListEntry::id);
  if (it == entries_.end()) {
    *error = std::format("no entry {}", id);
    return false;
  }
  entries_.erase(it);
  count_ = entries_.size();
  return SaveLocked(error);
}

bool ListStore::Update(uint64_t id, const nlohmann::json& patch, int64_t now,
                       ListEntry* stored, bool* found, std::string* error) {
  *found = false;
  if (!patch.is_object() || patch.empty()) {
    *error = R"(expected {"ttl": ...} and/or {"comment": ...})";
    return false;
  }
  for (const auto& [key, value] : patch.items()) {
    if (key != "ttl" && key != "comment") {
      *error = std::format("cannot change '{}'", key);
      return false;
    }
  }
  int64_t expires_at = -1;  // Unchanged.
  if (const auto it = patch.find("ttl"); it != patch.end()) {
    int64_t seconds = 0;
    if (it->is_null()) {
      expires_at = 0;
    } else if (!ParseTtl(*it, &seconds, error)) {
      return false;
    } else {
      expires_at = now + seconds;
    }
  }
  const auto comment = patch.find("comment");
  if (comment != patch.end() && !comment->is_string()) {
    *error = "comment must be a string";
    return false;
  }
  std::scoped_lock lock(mutex_);
  const auto it = std::ranges::find_if(entries_, [&](const ListEntry& e) {
    return e.id == id && (e.expires_at == 0 || e.expires_at > now);
  });
  if (it == entries_.end()) {
    *error = std::format("no entry {}", id);
    return false;
  }
  *found = true;
  ListEntry changed = *it;
  if (expires_at >= 0) changed.expires_at = expires_at;
  if (comment != patch.end()) changed.comment = comment->get<std::string>();
  std::swap(*it, changed);  // `changed` keeps the old entry until saved.
  if (!SaveLocked(error)) {
    std::swap(*it, changed);
    return false;
  }
  *stored = *it;
  return true;
}

std::vector<ListEntry> ListStore::Entries(int64_t now) const {
  std::scoped_lock lock(mutex_);
  std::vector<ListEntry> out;
  for (const ListEntry& entry : entries_) {
    if (entry.expires_at == 0 || entry.expires_at > now) out.push_back(entry);
  }
  return out;
}

std::optional<ListMatch> ListStore::Match(const ListMatchInput& input) const {
  if (count_.load(std::memory_order_relaxed) == 0) return std::nullopt;
  std::scoped_lock lock(mutex_);
  std::optional<ListMatch> block;
  for (const ListEntry& entry : entries_) {
    if (!EntryMatches(entry, input)) continue;
    if (entry.action == Action::kAllow) {
      return ListMatch{entry.id, Action::kAllow};
    }
    if (!block) block = ListMatch{entry.id, Action::kBlock};
  }
  return block;
}

}  // namespace bot_shield
