#include "admin/settings_api.h"

#include <cstdint>
#include <format>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "admin/server.h"
#include "admin/settings.h"
#include "common/log.h"
#include "config/config.h"
#include "config/settings.h"

namespace bot_shield {
namespace {

using Json = nlohmann::json;

AdminResponse Error(int status, std::string_view message,
                    std::string_view path = {}) {
  Json body = {{"error", message}};
  if (!path.empty()) body["path"] = path;
  return {status, std::move(body)};
}

AdminResponse Error(const SettingsError& error) {
  return Error(error.status, error.message, error.path);
}

std::string_view Source(const Json& layer, const Json& main_tree,
                        std::string_view path) {
  if (LayerValue(layer, path) != nullptr) return "console";
  if (LayerValue(main_tree, path) != nullptr) return "file";
  return "default";
}

bool IsSet(const SettingKey& key, const Config& config) {
  const Json value = key.get(config);
  return value.is_string() && !value.get<std::string>().empty();
}

bool PendingRestart(const SettingKey& key, const Config& effective,
                    const Config& running) {
  return key.apply == SettingApply::kRestart &&
         key.get(effective) != key.get(running);
}

Json KeyView(const SettingKey& key, const Config& effective,
             const Config& running, const Config& main, const Json& layer,
             const Json& main_tree) {
  static const Config kDefaults;
  const std::string_view source = Source(layer, main_tree, key.path);
  Json view = {{"path", key.path},
               {"type", SettingTypeName(key.type)},
               {"apply", SettingApplyName(key.apply)},
               {"secret", key.secret},
               {"source", source},
               {"pending_restart", PendingRestart(key, effective, running)}};
  if (!key.options.empty()) {
    view["options"] = Json::array();
    for (const std::string_view option : key.options) {
      view["options"].push_back(option);
    }
  }
  if (key.secret) {
    view["set"] = IsSet(key, effective);
    return view;
  }
  view["value"] = key.get(effective);
  view["default"] = key.get(kDefaults);
  if (source == "console" && LayerValue(main_tree, key.path) != nullptr) {
    view["file_value"] = key.get(main);
  }
  return view;
}

// Keys whose value or source differs between two layers.
Json Diff(const Config& before, const Json& layer_before, const Config& after,
          const Json& layer_after, const Json& main_tree,
          const Config& running) {
  Json changes = Json::array();
  for (const SettingKey& key : SettingKeys()) {
    const Json old_value = key.get(before);
    const Json new_value = key.get(after);
    const std::string_view old_source =
        Source(layer_before, main_tree, key.path);
    const std::string_view new_source =
        Source(layer_after, main_tree, key.path);
    if (old_value == new_value && old_source == new_source) continue;
    Json change = {{"path", key.path},
                   {"apply", SettingApplyName(key.apply)},
                   {"secret", key.secret},
                   {"source_before", old_source},
                   {"source_after", new_source},
                   {"pending_restart", PendingRestart(key, after, running)}};
    if (key.secret) {
      change["set_before"] = IsSet(key, before);
      change["set_after"] = IsSet(key, after);
      change["value_changed"] = old_value != new_value;
    } else {
      change["before"] = old_value;
      change["after"] = new_value;
    }
    changes.push_back(std::move(change));
  }
  return changes;
}

AdminResponse View(const AdminContext& context) {
  const SettingsLayer& settings = *context.settings;
  const auto verdicts = context.verdicts->snapshot();
  const Config& effective = *verdicts->config;
  const Json layer = settings.layer();
  const Json main_tree = settings.main_tree();
  const auto main = settings.main_config();
  Json keys = Json::array();
  bool pending = false;
  for (const SettingKey& key : SettingKeys()) {
    keys.push_back(
        KeyView(key, effective, *context.config, *main, layer, main_tree));
    pending = pending || keys.back()["pending_restart"].get<bool>();
  }
  const std::string load_error = settings.load_error();
  return {200,
          {{"editable", settings.editable()},
           {"revision", settings.revision()},
           {"error", load_error.empty() ? Json(nullptr) : Json(load_error)},
           {"pending_restart", pending},
           {"keys", std::move(keys)}}};
}

bool ParseChange(std::string_view body, SettingsChange* change,
                 std::string* error) {
  const Json json = Json::parse(body, nullptr, false);
  if (json.is_discarded() || !json.is_object()) {
    *error = "body must be a JSON object";
    return false;
  }
  const auto base = json.find("base_revision");
  if (base == json.end() || !base->is_string()) {
    *error = "base_revision is required";
    return false;
  }
  change->base_revision = base->get<std::string>();
  if (const auto set = json.find("set"); set != json.end()) {
    if (!set->is_object()) {
      *error = "set: expected {path: value}";
      return false;
    }
    for (const auto& [path, value] : set->items()) {
      change->set.emplace_back(path, value);
    }
  }
  if (const auto reset = json.find("reset"); reset != json.end()) {
    if (!reset->is_array()) {
      *error = "reset: expected a list of paths";
      return false;
    }
    for (const Json& path : *reset) {
      if (!path.is_string()) {
        *error = "reset: expected a list of paths";
        return false;
      }
      change->reset.push_back(path.get<std::string>());
    }
  }
  if (change->set.empty() && change->reset.empty()) {
    *error = "nothing to change";
    return false;
  }
  return true;
}

// Builds and publishes the verdict set of `prepared`, then commits it.
AdminResponse Apply(const PreparedSettings& prepared,
                    const AdminContext& context, int64_t now_ms,
                    std::string_view what) {
  const auto verdicts = context.verdicts->snapshot();
  const Json layer_before = context.settings->layer();
  const Json main_tree = context.settings->main_tree();
  Json changes = Diff(*verdicts->config, layer_before, *prepared.config,
                      prepared.layer, main_tree, *context.config);
  SettingsError commit_error;
  bool committed = false;
  std::string error;
  const bool ok = context.apply_settings(
      *prepared.config,
      [&] {
        committed = context.settings->Commit(prepared, now_ms, &commit_error);
        return committed;
      },
      &error);
  if (!ok) {
    if (!commit_error.message.empty()) return Error(commit_error);
    return Error(422, error);
  }
  std::string paths;
  for (const Json& change : changes) {
    if (!paths.empty()) paths += ", ";
    paths += change["path"].get<std::string>();
  }
  // Paths only: values may be secrets.
  log::Warn("admin: settings {} (console): {}", what,
            paths.empty() ? "no changes" : paths);
  return {200,
          {{"revision", prepared.revision}, {"changes", std::move(changes)}}};
}

}  // namespace

AdminResponse HandleSettingsRequest(std::string_view method,
                                    std::string_view rest,
                                    std::string_view body,
                                    const AdminContext& context,
                                    int64_t now_ms) {
  if (context.settings == nullptr || !context.apply_settings) {
    return Error(404, "settings unavailable");
  }
  if (rest.empty() && method == "GET") return View(context);
  if (rest == "/history") {
    if (method != "GET") return Error(405, "method not allowed");
    return {200,
            {{"revision", context.settings->revision()},
             {"versions", context.settings->History()}}};
  }
  if ((rest.empty() || rest == "/validate") && method == "POST") {
    SettingsChange change;
    std::string message;
    if (!ParseChange(body, &change, &message)) return Error(400, message);
    PreparedSettings prepared;
    SettingsError error;
    if (!context.settings->Prepare(change, &prepared, &error)) {
      return Error(error);
    }
    if (rest.empty()) return Apply(prepared, context, now_ms, "changed");
    const auto verdicts = context.verdicts->snapshot();
    return {
        200,
        {{"revision", prepared.revision},
         {"changes", Diff(*verdicts->config, context.settings->layer(),
                          *prepared.config, prepared.layer,
                          context.settings->main_tree(), *context.config)}}};
  }
  if (rest == "/rollback") {
    if (method != "POST") return Error(405, "method not allowed");
    const Json json = Json::parse(body, nullptr, false);
    if (json.is_discarded() || !json.is_object() ||
        !json.contains("revision") || !json["revision"].is_string()) {
      return Error(400, R"(expected {"revision": "..."})");
    }
    if (json.contains("base_revision") &&
        json["base_revision"] != context.settings->revision()) {
      return Error(409, "the settings changed since they were read");
    }
    PreparedSettings prepared;
    SettingsError error;
    if (!context.settings->PrepareRollback(json["revision"].get<std::string>(),
                                           &prepared, &error)) {
      return Error(error);
    }
    return Apply(
        prepared, context, now_ms,
        std::format("rolled back to {}", json["revision"].get<std::string>()));
  }
  return Error(rest.empty() || rest == "/validate" ? 405 : 404,
               rest.empty() || rest == "/validate" ? "method not allowed"
                                                   : "unknown endpoint");
}

}  // namespace bot_shield
