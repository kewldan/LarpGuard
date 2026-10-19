#include "admin/modes.h"

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/host.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

// "shop.example.com" or "*.example.com", normalized; "" when invalid.
std::string HostPattern(std::string_view host) {
  std::string pattern = NormalizeHost(host);
  const std::string_view name = pattern.starts_with("*.")
                                    ? std::string_view(pattern).substr(2)
                                    : std::string_view(pattern);
  if (!IsValidHostName(name)) return {};
  return pattern;
}

}  // namespace

ModeOverrides::ModeOverrides(std::string file) : file_(std::move(file)) {}

bool ModeOverrides::Load(std::string* error) {
  if (file_.empty()) return true;
  std::ifstream file(file_);
  if (!file) return true;  // First start.
  std::stringstream contents;
  contents << file.rdbuf();
  const nlohmann::json root =
      nlohmann::json::parse(contents.str(), nullptr, false);
  if (root.is_discarded() || !root.is_object()) {
    *error = std::format("{}: not a JSON object", file_);
    return false;
  }
  std::vector<std::pair<std::string, HostMode>> entries;
  for (const auto& [host, value] : root.items()) {
    HostMode mode = HostMode::kShadow;
    std::string pattern = HostPattern(host);
    if (pattern.empty() || !value.is_string() ||
        !ParseHostMode(value.get<std::string>(), &mode)) {
      *error = std::format("{}: bad entry '{}'", file_, host);
      return false;
    }
    entries.emplace_back(std::move(pattern), mode);
  }
  if (entries.size() > kMaxEntries) {
    *error = std::format("{}: more than {} hosts", file_, kMaxEntries);
    return false;
  }
  const std::scoped_lock lock(mutex_);
  entries_ = std::move(entries);
  return true;
}

bool ModeOverrides::Set(std::string_view host, HostMode mode,
                        std::string* error) {
  std::string pattern = HostPattern(host);
  if (pattern.empty()) {
    *error = std::format("invalid host '{}'", host);
    return false;
  }
  const std::scoped_lock lock(mutex_);
  const auto previous = entries_;
  const auto it = std::ranges::find(entries_, pattern,
                                    &std::pair<std::string, HostMode>::first);
  if (it != entries_.end()) {
    it->second = mode;
  } else if (entries_.size() >= kMaxEntries) {
    *error = "too many host mode overrides";
    return false;
  } else {
    entries_.emplace_back(std::move(pattern), mode);
  }
  if (!SaveLocked(error)) {
    entries_ = previous;
    return false;
  }
  return true;
}

bool ModeOverrides::Remove(std::string_view host, std::string* error) {
  const std::string pattern = NormalizeHost(host);
  const std::scoped_lock lock(mutex_);
  const auto it = std::ranges::find(entries_, pattern,
                                    &std::pair<std::string, HostMode>::first);
  if (it == entries_.end()) {
    *error = std::format("no console mode for '{}'", pattern);
    return false;
  }
  const auto previous = entries_;
  entries_.erase(it);
  if (!SaveLocked(error)) {
    entries_ = previous;
    return false;
  }
  return true;
}

std::vector<std::pair<std::string, HostMode>> ModeOverrides::Entries() const {
  const std::scoped_lock lock(mutex_);
  return entries_;
}

bool ModeOverrides::SaveLocked(std::string* error) const {
  if (file_.empty()) return true;
  nlohmann::json root = nlohmann::json::object();
  for (const auto& [host, mode] : entries_) root[host] = HostModeName(mode);
  const std::string temporary = file_ + ".tmp";
  {
    std::ofstream file(temporary, std::ios::trunc);
    file << root.dump(2) << "\n";
    if (!file) {
      *error = std::format("cannot write {}", temporary);
      return false;
    }
  }
  std::error_code ec;
  std::filesystem::rename(temporary, file_, ec);
  if (ec) {
    *error = std::format("cannot replace {}: {}", file_, ec.message());
    return false;
  }
  return true;
}

}  // namespace bot_shield
