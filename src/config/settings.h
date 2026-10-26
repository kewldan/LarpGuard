#ifndef BOT_SHIELD_CONFIG_SETTINGS_H_
#define BOT_SHIELD_CONFIG_SETTINGS_H_

#include <chrono>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "config/config.h"

namespace bot_shield {

// Every configuration key, for the console's settings (ADR-018): its YAML
// path, the shape of its value, when a change takes effect and whether it
// is a secret. Values are JSON in the form they take in YAML ("30s",
// "30/m", "0.0.0.0:443"), so a value read here and written to a layer
// parses back to the same setting.
enum class SettingType {
  kBool,
  kInt,
  kNumber,
  kString,
  kDuration,
  kRate,  // "30/m"; "" where the key allows off.
  kEndpoint,
  kEnum,
  kStrings,     // A list of strings.
  kHostModes,   // {host: shadow|enforce|off}.
  kRules,       // [{name, when, action, score}].
  kRateLimits,  // [{name, hosts, paths, methods, classes, key, rate, burst}].
  kThrottle,    // {rate, burst, key} or null.
};

// kLive: in the verdict set, applied without a restart. kRestart: read at
// startup. kYaml: only in the main file (paths the gateway reads or
// serves, sockets, listen addresses, the URL the CAPTCHA secret goes to).
enum class SettingApply { kLive, kRestart, kYaml };

struct SettingKey {
  std::string_view path;  // "captcha.round_timeout"
  SettingType type;
  SettingApply apply;
  bool secret = false;
  std::span<const std::string_view> options;  // For kEnum.
  nlohmann::json (*get)(const Config& config) = nullptr;
};

std::span<const SettingKey> SettingKeys();
// Null for an unknown path.
const SettingKey* FindSettingKey(std::string_view path);

std::string_view SettingTypeName(SettingType type);
std::string_view SettingApplyName(SettingApply apply);

// "5s", "250ms", "2m", "1h": the largest unit that divides the duration.
std::string FormatDuration(std::chrono::milliseconds duration);
// "30/m" for 30 per minute (periods of a second, minute, hour or day).
std::string FormatRate(int64_t count, std::chrono::milliseconds period);

// A settings layer: a YAML document of the configuration's schema with only
// some keys. Converted to a JSON object tree ({"captcha": {"rounds": 3}})
// so it can be edited and written back deterministically.
bool ParseSettingsLayer(std::string_view yaml, nlohmann::json* layer,
                        std::string* error);
// YAML text of `layer` (strings double-quoted), after `header` comment
// lines.
std::string EmitSettingsLayer(const nlohmann::json& layer,
                              std::string_view header);
// The registry keys set in `layer`, in registry order. False with `error`
// for a path that is not a key, or a key that only the main file may set.
bool SettingsLayerKeys(const nlohmann::json& layer,
                       std::vector<const SettingKey*>* keys,
                       std::string* error);

// The value at `path` in a layer tree; null pointer when absent.
const nlohmann::json* LayerValue(const nlohmann::json& layer,
                                 std::string_view path);
void SetLayerValue(nlohmann::json* layer, std::string_view path,
                   nlohmann::json value);
// Removes `path` and parents left empty.
void RemoveLayerValue(nlohmann::json* layer, std::string_view path);

// SHA-256 of every key's value in registry order (for a secret, only
// whether it is set), 12 hex digits: equal configurations hash equally on
// any gateway, and nothing about a secret can be guessed from it.
std::string ConfigHash(const Config& config);

// Keys whose value differs from `before` to `after`, in registry order:
// [{path, apply, secret, before, after (not for secrets: value_changed),
// pending_restart (a restart key `running` does not have yet)}].
nlohmann::json DiffSettings(const Config& before, const Config& after,
                            const Config& running);

// Checks the JSON shape of `value` for `key` (a bool for kBool, ...), so
// errors name the key; the configuration parser checks the rest.
bool CheckSettingValue(const SettingKey& key, const nlohmann::json& value,
                       std::string* error);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CONFIG_SETTINGS_H_
