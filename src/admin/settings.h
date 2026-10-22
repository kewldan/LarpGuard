#ifndef BOT_SHIELD_ADMIN_SETTINGS_H_
#define BOT_SHIELD_ADMIN_SETTINGS_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config/config.h"

namespace bot_shield {

// A change from the console: keys to set (secrets too, as strings; "" clears
// one) and keys to drop from the layer, so the main file decides again.
struct SettingsChange {
  std::string base_revision;
  std::vector<std::pair<std::string, nlohmann::json>> set;
  std::vector<std::string> reset;
};

// Why a change was refused: 400 (malformed), 409 (the layer changed since
// `base_revision`), 422 (the configuration does not accept it), 501 (no
// settings_file). `path` names the key when known.
struct SettingsError {
  int status = 422;
  std::string message;
  std::string path;
};

// A checked new layer, ready to commit.
struct PreparedSettings {
  std::string base_revision;
  nlohmann::json layer;
  std::string text;
  std::string revision;
  std::shared_ptr<const Config> config;  // Main file + the new layer.
};

// The console's settings layer (ADR-018): a YAML file of the configuration's
// schema over the main file, written only here. Keeps the main file's text
// as last read, so a console change never picks up unread edits of it, and
// the last kHistory layers for rollback. Thread-safe.
class SettingsLayer {
 public:
  static constexpr std::size_t kHistory = 20;
  static constexpr std::string_view kHeader =
      "# Written by bot-shield from the console (admin.settings_file).\n"
      "# Keys here override the main configuration file; edit that one, or\n"
      "# reset keys in the console, rather than this file.\n";

  explicit SettingsLayer(std::string main_file);

  SettingsLayer(const SettingsLayer&) = delete;
  SettingsLayer& operator=(const SettingsLayer&) = delete;

  // Reads the main file and, from its admin.settings_file, the layer into
  // `*config` (defaults first). False only when the main file is bad, or
  // with `strict` (--check-config) when the layer is. Otherwise a bad layer
  // is set aside (as <file>.rejected): the newest good version from the
  // history is used, or none, and load_error() says why.
  bool Load(Config* config, bool strict, std::string* error);
  // SIGHUP and POST /reload: both files again; nothing changes on error.
  bool Reload(Config* config, std::string* error);

  bool editable() const;
  std::string revision() const;
  std::string load_error() const;
  nlohmann::json layer() const;
  // The main file as a tree (for the source of each value) and parsed
  // alone (for the value a console key overrides).
  nlohmann::json main_tree() const;
  std::shared_ptr<const Config> main_config() const;

  bool Prepare(const SettingsChange& change, PreparedSettings* out,
               SettingsError* error) const;
  bool PrepareRollback(std::string_view revision, PreparedSettings* out,
                       SettingsError* error) const;
  // Writes the layer (temporary file, fsync, rename; mode 0600) and keeps
  // the replaced one in the history. 409 when the layer changed since
  // Prepare.
  bool Commit(const PreparedSettings& prepared, int64_t now_ms,
              SettingsError* error);
  // Newest first: {revision, replaced_at_ms, keys}.
  nlohmann::json History() const;

 private:
  struct Version {
    std::string revision;
    int64_t replaced_at_ms = 0;
    std::string text;
  };

  // Parses `layer_text` over `main` into `*config`.
  static bool ApplyLayer(const Config& main, std::string_view layer_text,
                         nlohmann::json* layer, Config* config,
                         std::string* error);
  bool ReadMain(Config* main, std::string* text, std::string* error) const;
  bool PrepareLocked(const nlohmann::json& layer,
                     const std::vector<std::string>& changed,
                     PreparedSettings* out, SettingsError* error) const;
  void LoadHistoryLocked();
  bool SaveHistoryLocked(std::string* error) const;

  const std::string main_file_;
  mutable std::mutex mutex_;
  std::string layer_file_;
  std::string main_text_;
  nlohmann::json main_tree_ = nlohmann::json::object();
  std::shared_ptr<const Config> main_config_;
  nlohmann::json layer_ = nlohmann::json::object();
  std::string layer_text_;
  std::string revision_;
  std::string load_error_;
  std::vector<Version> history_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_SETTINGS_H_
