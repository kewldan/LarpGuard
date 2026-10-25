#include "config/settings.h"

#include <gtest/gtest.h>
#include <sys/stat.h>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "admin/settings.h"
#include "config/config.h"

namespace bot_shield {
namespace {

using Json = nlohmann::json;
using std::chrono::milliseconds;

std::string ReadText(const std::string& path) {
  std::ifstream file(path);
  std::stringstream contents;
  contents << file.rdbuf();
  return contents.str();
}

std::string DeployFile() {
  return std::string(BOT_SHIELD_SOURCE_DIR) + "/deploy/bot-shield.yaml";
}

// Leaf paths of a YAML tree, stopping at registry keys.
void Leaves(const Json& node, const std::string& prefix,
            std::vector<std::string>* out) {
  for (const auto& [key, value] : node.items()) {
    const std::string path =
        prefix.empty() ? key : std::format("{}.{}", prefix, key);
    if (FindSettingKey(path) != nullptr || !value.is_object()) {
      out->push_back(path);
    } else {
      Leaves(value, path, out);
    }
  }
}

// Every key of `config` written to one layer and read back over defaults.
void ExpectRoundTrip(const Config& config) {
  Json layer = Json::object();
  for (const SettingKey& key : SettingKeys()) {
    SetLayerValue(&layer, key.path, key.get(config));
  }
  const std::string text = EmitSettingsLayer(layer, "# test\n");
  Config parsed;
  std::string error;
  ASSERT_TRUE(ParseConfig(text, &parsed, &error)) << error << "\n" << text;
  for (const SettingKey& key : SettingKeys()) {
    EXPECT_EQ(key.get(parsed), key.get(config)) << key.path;
  }
  Json reread;
  ASSERT_TRUE(ParseSettingsLayer(text, &reread, &error)) << error;
  EXPECT_EQ(reread, layer);
}

TEST(SettingsRegistryTest, CoversTheDocumentedConfiguration) {
  const std::string text = ReadText(DeployFile());
  ASSERT_FALSE(text.empty());
  Json tree;
  std::string error;
  ASSERT_TRUE(ParseSettingsLayer(text, &tree, &error)) << error;
  std::vector<std::string> paths;
  Leaves(tree, "", &paths);
  for (const std::string& path : paths) {
    EXPECT_NE(FindSettingKey(path), nullptr) << path << " is not registered";
  }
  // Every key is documented (some only as a commented example).
  for (const SettingKey& key : SettingKeys()) {
    const std::size_t dot = key.path.rfind('.');
    const std::string_view leaf =
        dot == std::string_view::npos ? key.path : key.path.substr(dot + 1);
    EXPECT_NE(text.find(std::string(leaf) + ":"), std::string::npos)
        << key.path << " is not in deploy/bot-shield.yaml";
    EXPECT_NE(key.get, nullptr) << key.path;
    if (key.type == SettingType::kEnum) {
      EXPECT_FALSE(key.options.empty()) << key.path;
    }
  }
}

TEST(SettingsRegistryTest, ValuesRoundTrip) {
  ExpectRoundTrip(Config());
  Config deploy;
  std::string error;
  ASSERT_TRUE(LoadConfigFile(DeployFile(), &deploy, &error)) << error;
  ExpectRoundTrip(deploy);
  Config custom;
  ASSERT_TRUE(ParseConfig(R"(
listen: {http: "", https: "[::1]:8443"}
mode: enforce
policy:
  thresholds: {suspicious: 20, bot: 60}
  actions: {suspicious: challenge, bot: tarpit, verified_bot: allow}
  hosts: {"*.shop.test": enforce, api.test: "off"}
rules:
  - name: quoted
    when: 'header("x-a") == "b: c" and path ~ "/x*"'
    action: score
    score: -15
  - {name: admins, when: 'path ~ "/admin*"', action: block}
rate_limits:
  - {name: login, paths: [/login], methods: [POST], key: [ip], rate: 5/m}
  - {name: api, key: ["header:x-api-key"], rate: 100/s, burst: 200}
  - {name: failures, key: [ip], rate: 5/h, statuses: [401, 403]}
throttle: {rate: 30/m, burst: 10, key: [ip_prefix]}
connection_limits: {new_per_ip: 30/s, new_burst_per_ip: 5}
crawlers: {ai: block}
model: {threshold: 0.65}
timeouts: {client_hello: 1500ms, idle: 300s}
captcha:
  provider: turnstile
  site_key: "0x4AAA"
  secret: "s3cr3t: with colon"
xdp: {syn_rate: 200/s}
events: {nats: "nats://127.0.0.1:4222", token: "t"}
log_level: debug
)",
                          &custom, &error))
      << error;
  ExpectRoundTrip(custom);
}

TEST(SettingsRegistryTest, Formats) {
  EXPECT_EQ(FormatDuration(milliseconds(250)), "250ms");
  EXPECT_EQ(FormatDuration(milliseconds(5000)), "5s");
  EXPECT_EQ(FormatDuration(milliseconds(300000)), "5m");
  EXPECT_EQ(FormatDuration(std::chrono::hours(24)), "24h");
  EXPECT_EQ(FormatDuration(milliseconds(1500)), "1500ms");
  EXPECT_EQ(FormatDuration(milliseconds(0)), "0s");
  EXPECT_EQ(FormatRate(30, std::chrono::minutes(1)), "30/m");
  EXPECT_EQ(FormatRate(2, std::chrono::hours(24)), "2/d");
  EXPECT_EQ(FormatRate(7, std::chrono::seconds(1)), "7/s");
}

TEST(SettingsLayerTreeTest, KeysAndEdits) {
  Json layer = Json::object();
  SetLayerValue(&layer, "captcha.rounds", 3);
  SetLayerValue(&layer, "mode", "enforce");
  SetLayerValue(&layer, "policy.thresholds.bot", 80);
  std::vector<const SettingKey*> keys;
  std::string error;
  ASSERT_TRUE(SettingsLayerKeys(layer, &keys, &error)) << error;
  ASSERT_EQ(keys.size(), 3u);
  EXPECT_EQ(keys[0]->path, "mode");  // Registry order.
  ASSERT_NE(LayerValue(layer, "captcha.rounds"), nullptr);
  EXPECT_EQ(*LayerValue(layer, "captcha.rounds"), 3);
  EXPECT_EQ(LayerValue(layer, "captcha.difficulty"), nullptr);
  RemoveLayerValue(&layer, "policy.thresholds.bot");
  EXPECT_FALSE(layer.contains("policy"));  // Empty parents go too.

  SetLayerValue(&layer, "captcha.verify_url", "https://evil.test/");
  EXPECT_FALSE(SettingsLayerKeys(layer, &keys, &error));
  EXPECT_EQ(error, "captcha.verify_url: can only be set in the main file");
  RemoveLayerValue(&layer, "captcha.verify_url");
  SetLayerValue(&layer, "captcha.color", "red");
  EXPECT_FALSE(SettingsLayerKeys(layer, &keys, &error));
  EXPECT_EQ(error, "unknown key 'captcha.color'");

  EXPECT_FALSE(ParseSettingsLayer("[1, 2]", &layer, &error));
  ASSERT_TRUE(ParseSettingsLayer("", &layer, &error));
  EXPECT_TRUE(layer.empty());
  EXPECT_EQ(EmitSettingsLayer(layer, "# h\n"), "# h\n");
}

TEST(SettingsLayerTreeTest, ScalarsKeepTheirType) {
  Json layer;
  std::string error;
  ASSERT_TRUE(ParseSettingsLayer(
      "a: true\nb: \"true\"\nc: 12\nd: \"12\"\ne: 0.5\nf: 5s\ng: ~\n", &layer,
      &error));
  EXPECT_EQ(layer["a"], true);
  EXPECT_EQ(layer["b"], "true");
  EXPECT_EQ(layer["c"], 12);
  EXPECT_EQ(layer["d"], "12");
  EXPECT_EQ(layer["e"], 0.5);
  EXPECT_EQ(layer["f"], "5s");
  EXPECT_TRUE(layer["g"].is_null());
}

TEST(SettingsLayerTreeTest, ChecksValueShapes) {
  std::string error;
  const SettingKey& rounds = *FindSettingKey("captcha.rounds");
  EXPECT_TRUE(CheckSettingValue(rounds, 3, &error));
  EXPECT_FALSE(CheckSettingValue(rounds, "3", &error));
  EXPECT_EQ(error, "captcha.rounds: expected an integer");
  const SettingKey& provider = *FindSettingKey("captcha.provider");
  EXPECT_TRUE(CheckSettingValue(provider, "hcaptcha", &error));
  EXPECT_FALSE(CheckSettingValue(provider, "funcaptcha", &error));
  const SettingKey& rules = *FindSettingKey("rules");
  EXPECT_TRUE(CheckSettingValue(
      rules, Json::parse(R"([{"name":"a","when":"true","action":"block"}])"),
      &error));
  EXPECT_FALSE(CheckSettingValue(
      rules, Json::parse(R"([{"name":"a","score":"x"}])"), &error));
  const SettingKey& throttle = *FindSettingKey("throttle");
  EXPECT_TRUE(CheckSettingValue(throttle, nullptr, &error));
  EXPECT_FALSE(CheckSettingValue(*FindSettingKey("workers"), nullptr, &error));
}

TEST(SettingsConfigTest, CaptchaSecretAndThrottleReset) {
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(
      "captcha: {provider: hcaptcha, site_key: k, secret: hunter2}\n", &config,
      &error))
      << error;
  EXPECT_EQ(config.captcha_secret, "hunter2");
  EXPECT_FALSE(ParseConfig("captcha: {secret_file: /x}\n", &config, &error));
  EXPECT_EQ(error,
            "captcha.secret: set either secret or secret_file, not both");
  // The error never carries the secret.
  EXPECT_EQ(error.find("hunter2"), std::string::npos);

  ASSERT_TRUE(ParseConfig("throttle: {rate: 10/m}\n", &config, &error));
  ASSERT_TRUE(config.throttle.has_value());
  ASSERT_TRUE(ParseConfig("throttle: ~\n", &config, &error)) << error;
  EXPECT_FALSE(config.throttle.has_value());
  ASSERT_TRUE(ParseConfig("admin: {settings_file: /var/lib/bs/s.yaml}\n",
                          &config, &error));
  EXPECT_EQ(config.admin_settings_file, "/var/lib/bs/s.yaml");
}

class SettingsLayerTest : public testing::Test {
 protected:
  void SetUp() override {
    dir_ = std::filesystem::temp_directory_path() /
           ("bs_settings_" +
            std::string(
                testing::UnitTest::GetInstance()->current_test_info()->name()));
    std::filesystem::remove_all(dir_);
    std::filesystem::create_directories(dir_);
    main_ = (dir_ / "bot-shield.yaml").string();
    layer_ = (dir_ / "settings.yaml").string();
    std::ofstream(main_) << "admin: {settings_file: " << layer_
                         << "}\ncaptcha: {rounds: 2, site_key: file-key}\n";
  }
  void TearDown() override { std::filesystem::remove_all(dir_); }

  std::filesystem::path dir_;
  std::string main_;
  std::string layer_;
};

TEST_F(SettingsLayerTest, PrepareCommitHistoryRollback) {
  SettingsLayer settings(main_);
  Config config;
  std::string error;
  ASSERT_TRUE(settings.Load(&config, false, &error)) << error;
  EXPECT_TRUE(settings.editable());
  EXPECT_TRUE(settings.load_error().empty());
  const std::string first = settings.revision();

  SettingsChange change{first, {{"captcha.rounds", 4}}, {}};
  PreparedSettings prepared;
  SettingsError failure;
  ASSERT_TRUE(settings.Prepare(change, &prepared, &failure)) << failure.message;
  EXPECT_EQ(prepared.config->captcha_rounds, 4);
  EXPECT_EQ(prepared.config->captcha_site_key, "file-key");
  ASSERT_TRUE(settings.Commit(prepared, 1000, &failure)) << failure.message;
  EXPECT_NE(settings.revision(), first);
  struct stat info{};
  ASSERT_EQ(stat(layer_.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777, 0600);
  EXPECT_NE(ReadText(layer_).find("rounds: 4"), std::string::npos);

  // A second change on the stale revision is refused.
  EXPECT_FALSE(settings.Prepare(change, &prepared, &failure));
  EXPECT_EQ(failure.status, 409);
  EXPECT_FALSE(settings.Commit(prepared, 2000, &failure));
  EXPECT_EQ(failure.status, 409);

  change = {settings.revision(), {{"captcha.rounds", 9}}, {}};
  EXPECT_FALSE(settings.Prepare(change, &prepared, &failure));
  EXPECT_EQ(failure.status, 422);
  EXPECT_EQ(failure.path, "captcha.rounds");
  EXPECT_EQ(failure.message, "captcha.rounds: expected 1..5");
  change = {
      settings.revision(), {{"captcha.verify_url", "https://x.test"}}, {}};
  EXPECT_FALSE(settings.Prepare(change, &prepared, &failure));
  EXPECT_EQ(failure.status, 422);
  change = {settings.revision(), {{"captcha.nope", 1}}, {}};
  EXPECT_FALSE(settings.Prepare(change, &prepared, &failure));
  EXPECT_EQ(failure.status, 400);
  // A cross-key check names the changed key.
  change = {settings.revision(), {{"captcha.provider", "turnstile"}}, {}};
  EXPECT_FALSE(settings.Prepare(change, &prepared, &failure));
  EXPECT_EQ(failure.path, "captcha.provider");

  const std::string second = settings.revision();
  change = {second, {{"captcha.secret", "top"}}, {"captcha.rounds"}};
  ASSERT_TRUE(settings.Prepare(change, &prepared, &failure)) << failure.message;
  EXPECT_EQ(prepared.config->captcha_rounds, 2);  // The file decides again.
  ASSERT_TRUE(settings.Commit(prepared, 3000, &failure));

  const Json history = settings.History();
  ASSERT_EQ(history.size(), 2u);
  EXPECT_EQ(history[0]["revision"], second);
  EXPECT_EQ(history[0]["replaced_at_ms"], 3000);
  EXPECT_EQ(history[0]["keys"], Json::array({"captcha.rounds"}));
  EXPECT_EQ(history[1]["revision"], first);

  ASSERT_TRUE(settings.PrepareRollback(second, &prepared, &failure));
  EXPECT_EQ(prepared.config->captcha_rounds, 4);
  EXPECT_TRUE(prepared.config->captcha_secret.empty());
  ASSERT_TRUE(settings.Commit(prepared, 4000, &failure));
  EXPECT_EQ(settings.revision(), second);
  EXPECT_FALSE(settings.PrepareRollback("0000", &prepared, &failure));
  EXPECT_EQ(failure.status, 404);

  // A restart reads the layer and the history back.
  SettingsLayer restarted(main_);
  Config reloaded;
  ASSERT_TRUE(restarted.Load(&reloaded, false, &error)) << error;
  EXPECT_EQ(reloaded.captcha_rounds, 4);
  EXPECT_EQ(restarted.revision(), second);
  EXPECT_EQ(restarted.History().size(), 2u);
}

TEST_F(SettingsLayerTest, BadLayerFallsBackWithoutFailing) {
  {
    SettingsLayer settings(main_);
    Config config;
    std::string error;
    ASSERT_TRUE(settings.Load(&config, false, &error)) << error;
    SettingsChange change{settings.revision(), {{"captcha.rounds", 3}}, {}};
    PreparedSettings prepared;
    SettingsError failure;
    ASSERT_TRUE(settings.Prepare(change, &prepared, &failure));
    ASSERT_TRUE(settings.Commit(prepared, 1000, &failure));
    change = {settings.revision(), {{"captcha.rounds", 5}}, {}};
    ASSERT_TRUE(settings.Prepare(change, &prepared, &failure));
    ASSERT_TRUE(settings.Commit(prepared, 2000, &failure));
  }
  // Edited by hand into something the parser refuses.
  std::ofstream(layer_) << "captcha: {rounds: 7}\n";
  SettingsLayer settings(main_);
  Config config;
  std::string error;
  EXPECT_FALSE(settings.Load(&config, true, &error));  // --check-config.
  Config fallback;
  ASSERT_TRUE(settings.Load(&fallback, false, &error)) << error;
  EXPECT_EQ(fallback.captcha_rounds, 3);  // The newest good version.
  EXPECT_NE(settings.load_error().find("captcha.rounds: expected 1..5"),
            std::string::npos);
  EXPECT_TRUE(std::filesystem::exists(layer_ + ".rejected"));

  // Main-file-only keys in the layer are refused the same way.
  std::filesystem::remove(layer_ + ".history");
  std::ofstream(layer_) << "admin: {socket: /tmp/x.sock}\n";
  ASSERT_TRUE(settings.Load(&fallback, false, &error)) << error;
  EXPECT_EQ(fallback.captcha_rounds, 2);
  EXPECT_TRUE(fallback.admin_socket.empty());
  EXPECT_NE(settings.load_error().find("can only be set in the main file"),
            std::string::npos);

  // Reload is strict: the running configuration stays.
  EXPECT_FALSE(settings.Reload(&config, &error));
  std::ofstream(layer_) << "whoami: true\n";
  ASSERT_TRUE(settings.Reload(&config, &error)) << error;
  EXPECT_TRUE(config.whoami);
  EXPECT_TRUE(settings.load_error().empty());
}

TEST_F(SettingsLayerTest, ReadOnlyWithoutSettingsFile) {
  std::ofstream(main_) << "whoami: true\n";
  SettingsLayer settings(main_);
  Config config;
  std::string error;
  ASSERT_TRUE(settings.Load(&config, false, &error)) << error;
  EXPECT_FALSE(settings.editable());
  SettingsChange change{settings.revision(), {{"whoami", false}}, {}};
  PreparedSettings prepared;
  SettingsError failure;
  EXPECT_FALSE(settings.Prepare(change, &prepared, &failure));
  EXPECT_EQ(failure.status, 501);
  std::ofstream(main_) << "whoami: [\n";
  EXPECT_FALSE(settings.Load(&config, false, &error));  // Main file errors.
}

}  // namespace
}  // namespace bot_shield
