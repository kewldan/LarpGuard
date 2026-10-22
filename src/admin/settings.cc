#include "admin/settings.h"

#include <fcntl.h>  // IWYU pragma: keep
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/hash.h"
#include "config/config.h"
#include "config/settings.h"

namespace bot_shield {
namespace {

using Json = nlohmann::json;

constexpr std::size_t kRevisionChars = 16;

bool ReadFile(const std::string& path, std::string* contents, bool* missing) {
  std::ifstream file(path);
  if (!file) {
    *missing = !std::filesystem::exists(path);
    return false;
  }
  std::stringstream stream;
  stream << file.rdbuf();
  *contents = stream.str();
  return true;
}

// Temporary file next to `path`, fsync, rename: readers see the old or the
// new contents, never a part.
bool WriteFileAtomic(const std::string& path, std::string_view contents,
                     std::string* error) {
  const std::string temporary = path + ".tmp";
  // open() and O_* come from <fcntl.h> on Linux, <sys/fcntl.h> on macOS.
  // NOLINTBEGIN(misc-include-cleaner)
  const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  // NOLINTEND(misc-include-cleaner)
  if (fd < 0) {
    *error =
        std::format("cannot write {}: {}", temporary, std::strerror(errno));
    return false;
  }
  std::size_t written = 0;
  bool ok = true;
  while (written < contents.size()) {
    const ssize_t n =
        ::write(fd, contents.data() + written, contents.size() - written);
    if (n < 0) {
      if (errno == EINTR) continue;
      ok = false;
      break;
    }
    written += static_cast<std::size_t>(n);
  }
  ok = ok && ::fsync(fd) == 0;
  ok = ::close(fd) == 0 && ok;
  if (!ok) {
    *error =
        std::format("cannot write {}: {}", temporary, std::strerror(errno));
    return false;
  }
  std::error_code ec;
  std::filesystem::rename(temporary, path, ec);
  if (ec) {
    *error = std::format("cannot replace {}: {}", path, ec.message());
    return false;
  }
  return true;
}

std::string Revision(std::string_view text) {
  return Sha256Hex(text, kRevisionChars);
}

Json KeysOf(const Json& layer) {
  Json keys = Json::array();
  std::vector<const SettingKey*> found;
  std::string error;
  if (SettingsLayerKeys(layer, &found, &error)) {
    for (const SettingKey* key : found) keys.push_back(key->path);
  }
  return keys;
}

// The key a configuration error is about: the longest changed path the
// message starts with, else a changed key in the section it names, else
// the only changed key.
std::string ErrorPath(std::string_view message,
                      const std::vector<std::string>& changed) {
  std::string best;
  for (const SettingKey& key : SettingKeys()) {
    const std::string_view path = key.path;
    if (message.starts_with(path) && message.size() > path.size() &&
        std::string_view(": '[").find(message[path.size()]) !=
            std::string_view::npos &&
        path.size() > best.size()) {
      best = path;
    }
  }
  if (!best.empty()) return best;
  const std::string_view section =
      message.substr(0, message.find_first_of(": "));
  for (const std::string& path : changed) {
    if (path.starts_with(section) &&
        (path.size() == section.size() || path[section.size()] == '.')) {
      return path;
    }
  }
  return changed.size() == 1 ? changed.front() : std::string();
}

}  // namespace

SettingsLayer::SettingsLayer(std::string main_file)
    : main_file_(std::move(main_file)),
      main_config_(std::make_shared<const Config>()) {}

bool SettingsLayer::ReadMain(Config* main, std::string* text,
                             std::string* error) const {
  bool missing = false;
  if (!ReadFile(main_file_, text, &missing)) {
    *error = std::format("cannot open {}", main_file_);
    return false;
  }
  if (!ParseConfig(*text, main, error)) {
    *error = std::format("{}: {}", main_file_, *error);
    return false;
  }
  return true;
}

bool SettingsLayer::ApplyLayer(const Config& main, std::string_view layer_text,
                               Json* layer, Config* config,
                               std::string* error) {
  std::vector<const SettingKey*> keys;
  if (!ParseSettingsLayer(layer_text, layer, error) ||
      !SettingsLayerKeys(*layer, &keys, error)) {
    return false;
  }
  *config = main;
  return ParseConfig(layer_text, config, error);
}

bool SettingsLayer::Load(Config* config, bool strict, std::string* error) {
  Config main = *config;
  std::string main_text;
  if (!ReadMain(&main, &main_text, error)) return false;
  const std::scoped_lock lock(mutex_);
  layer_file_ = main.admin_settings_file;
  main_text_ = std::move(main_text);
  if (!ParseSettingsLayer(main_text_, &main_tree_, error)) return false;
  main_config_ = std::make_shared<const Config>(main);
  layer_ = Json::object();
  layer_text_.clear();
  load_error_.clear();
  *config = main;
  if (layer_file_.empty()) {
    revision_ = Revision(layer_text_);
    return true;
  }
  LoadHistoryLocked();
  std::string text;
  bool missing = false;
  if (!ReadFile(layer_file_, &text, &missing) && !missing) {
    *error = std::format("cannot read {}", layer_file_);
    if (strict) return false;
    load_error_ = *error;
  }
  Json layer;
  Config layered;
  std::string layer_error;
  if (load_error_.empty() &&
      ApplyLayer(main, text, &layer, &layered, &layer_error)) {
    layer_ = std::move(layer);
    layer_text_ = std::move(text);
    *config = std::move(layered);
    revision_ = Revision(layer_text_);
    return true;
  }
  if (load_error_.empty()) {
    load_error_ = std::format("{}: {}", layer_file_, layer_error);
    if (strict) {
      *error = load_error_;
      return false;
    }
    std::error_code ec;
    std::filesystem::copy_file(
        layer_file_, layer_file_ + ".rejected",
        std::filesystem::copy_options::overwrite_existing, ec);
  }
  // The newest version from the history that still works, else none.
  for (const Version& version : history_) {
    if (ApplyLayer(main, version.text, &layer, &layered, &layer_error)) {
      layer_ = std::move(layer);
      layer_text_ = version.text;
      *config = std::move(layered);
      load_error_ += std::format("; using version {}", version.revision);
      break;
    }
  }
  revision_ = Revision(layer_text_);
  return true;
}

bool SettingsLayer::Reload(Config* config, std::string* error) {
  Config main;
  std::string main_text;
  if (!ReadMain(&main, &main_text, error)) return false;
  Json main_tree;
  if (!ParseSettingsLayer(main_text, &main_tree, error)) return false;
  const std::scoped_lock lock(mutex_);
  std::string text = layer_text_;
  if (!layer_file_.empty()) {
    bool missing = false;
    if (!ReadFile(layer_file_, &text, &missing)) text.clear();
  }
  Json layer;
  Config layered;
  if (!ApplyLayer(main, text, &layer, &layered, error)) {
    *error = std::format("{}: {}", layer_file_, *error);
    return false;
  }
  main_text_ = std::move(main_text);
  main_tree_ = std::move(main_tree);
  main_config_ = std::make_shared<const Config>(std::move(main));
  layer_ = std::move(layer);
  layer_text_ = std::move(text);
  revision_ = Revision(layer_text_);
  load_error_.clear();
  *config = std::move(layered);
  return true;
}

bool SettingsLayer::editable() const {
  const std::scoped_lock lock(mutex_);
  return !layer_file_.empty();
}

std::string SettingsLayer::revision() const {
  const std::scoped_lock lock(mutex_);
  return revision_;
}

std::string SettingsLayer::load_error() const {
  const std::scoped_lock lock(mutex_);
  return load_error_;
}

Json SettingsLayer::layer() const {
  const std::scoped_lock lock(mutex_);
  return layer_;
}

Json SettingsLayer::main_tree() const {
  const std::scoped_lock lock(mutex_);
  return main_tree_;
}

std::shared_ptr<const Config> SettingsLayer::main_config() const {
  const std::scoped_lock lock(mutex_);
  return main_config_;
}

bool SettingsLayer::Prepare(const SettingsChange& change, PreparedSettings* out,
                            SettingsError* error) const {
  const std::scoped_lock lock(mutex_);
  if (layer_file_.empty()) {
    *error = {501, "admin.settings_file is not set: settings are read-only",
              ""};
    return false;
  }
  if (change.base_revision != revision_) {
    *error = {409, "the settings changed since they were read", ""};
    return false;
  }
  Json layer = layer_;
  std::vector<std::string> changed;
  for (const auto& [path, value] : change.set) {
    const SettingKey* key = FindSettingKey(path);
    if (key == nullptr) {
      *error = {400, std::format("unknown key '{}'", path), path};
      return false;
    }
    if (key->apply == SettingApply::kYaml) {
      *error = {422, std::format("{}: can only be set in the main file", path),
                path};
      return false;
    }
    std::string message;
    if (!CheckSettingValue(*key, value, &message)) {
      *error = {400, message, path};
      return false;
    }
    SetLayerValue(&layer, path, value);
    changed.push_back(path);
  }
  for (const std::string& path : change.reset) {
    if (FindSettingKey(path) == nullptr) {
      *error = {400, std::format("unknown key '{}'", path), path};
      return false;
    }
    RemoveLayerValue(&layer, path);
    changed.push_back(path);
  }
  return PrepareLocked(layer, changed, out, error);
}

bool SettingsLayer::PrepareRollback(std::string_view revision,
                                    PreparedSettings* out,
                                    SettingsError* error) const {
  const std::scoped_lock lock(mutex_);
  if (layer_file_.empty()) {
    *error = {501, "admin.settings_file is not set: settings are read-only",
              ""};
    return false;
  }
  const auto it = std::ranges::find(history_, revision, &Version::revision);
  if (it == history_.end()) {
    *error = {404, std::format("no version {}", revision), ""};
    return false;
  }
  Json layer;
  std::string message;
  if (!ParseSettingsLayer(it->text, &layer, &message)) {
    *error = {422, message, ""};
    return false;
  }
  return PrepareLocked(layer, {}, out, error);
}

bool SettingsLayer::PrepareLocked(const Json& layer,
                                  const std::vector<std::string>& changed,
                                  PreparedSettings* out,
                                  SettingsError* error) const {
  std::string text = EmitSettingsLayer(layer, kHeader);
  Json parsed;
  auto config = std::make_shared<Config>();
  std::string message;
  if (!ApplyLayer(*main_config_, text, &parsed, config.get(), &message)) {
    *error = {422, message, ErrorPath(message, changed)};
    return false;
  }
  out->base_revision = revision_;
  out->layer = std::move(parsed);
  out->revision = Revision(text);
  out->text = std::move(text);
  out->config = std::move(config);
  return true;
}

bool SettingsLayer::Commit(const PreparedSettings& prepared, int64_t now_ms,
                           SettingsError* error) {
  const std::scoped_lock lock(mutex_);
  if (prepared.base_revision != revision_) {
    *error = {409, "the settings changed since they were read", ""};
    return false;
  }
  std::string message;
  if (!WriteFileAtomic(layer_file_, prepared.text, &message)) {
    *error = {500, message, ""};
    return false;
  }
  if (prepared.revision != revision_) {
    history_.insert(history_.begin(), {revision_, now_ms, layer_text_});
    std::erase_if(history_, [&](const Version& version) {
      return version.revision == prepared.revision;
    });
    if (history_.size() > kHistory) history_.resize(kHistory);
    // The layer is written; a history that cannot be saved only costs the
    // rollback after a restart.
    SaveHistoryLocked(&message);
  }
  layer_ = prepared.layer;
  layer_text_ = prepared.text;
  revision_ = prepared.revision;
  load_error_.clear();
  return true;
}

Json SettingsLayer::History() const {
  const std::scoped_lock lock(mutex_);
  Json out = Json::array();
  for (const Version& version : history_) {
    Json layer;
    std::string error;
    if (!ParseSettingsLayer(version.text, &layer, &error)) continue;
    out.push_back({{"revision", version.revision},
                   {"replaced_at_ms", version.replaced_at_ms},
                   {"keys", KeysOf(layer)}});
  }
  return out;
}

void SettingsLayer::LoadHistoryLocked() {
  history_.clear();
  std::string text;
  bool missing = false;
  if (!ReadFile(layer_file_ + ".history", &text, &missing)) return;
  const Json root = Json::parse(text, nullptr, false);
  if (root.is_discarded() || !root.is_array()) return;
  for (const Json& item : root) {
    if (!item.is_object() || !item.contains("text") ||
        !item["text"].is_string()) {
      continue;
    }
    Version version;
    version.text = item["text"].get<std::string>();
    version.revision = Revision(version.text);
    version.replaced_at_ms = item.value("replaced_at_ms", int64_t{0});
    history_.push_back(std::move(version));
    if (history_.size() == kHistory) break;
  }
}

bool SettingsLayer::SaveHistoryLocked(std::string* error) const {
  Json root = Json::array();
  for (const Version& version : history_) {
    root.push_back(
        {{"replaced_at_ms", version.replaced_at_ms}, {"text", version.text}});
  }
  return WriteFileAtomic(layer_file_ + ".history", root.dump(1) + "\n", error);
}

}  // namespace bot_shield
