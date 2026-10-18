#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "config/config.h"
#include "fp/http_request.h"
#include "model/features.h"
#include "model/gbdt.h"

namespace bot_shield {
namespace {

nlohmann::json Fixture() {
  std::ifstream file(std::string(BOT_SHIELD_SOURCE_DIR) +
                     "/tests/data/gbdt_fixture.json");
  std::stringstream contents;
  contents << file.rdbuf();
  return nlohmann::json::parse(contents.str());
}

// Same predictions as tools/train_model.py (written by its --fixture).
TEST(GbdtModelTest, MatchesTheTrainingScript) {
  const nlohmann::json fixture = Fixture();
  GbdtModel model;
  std::string error;
  ASSERT_TRUE(GbdtModel::Parse(fixture["model"].dump(), &model, &error))
      << error;
  EXPECT_EQ(model.tree_count(), 10U);
  const auto& samples = fixture["samples"];
  const auto& expected = fixture["expected"];
  ASSERT_EQ(samples.size(), expected.size());
  for (std::size_t i = 0; i < samples.size(); ++i) {
    const auto features = samples[i].get<std::vector<float>>();
    EXPECT_NEAR(model.Predict(features), expected[i].get<double>(), 1e-5)
        << "sample " << i;
  }
}

TEST(GbdtModelTest, RejectsBadModels) {
  const nlohmann::json good = Fixture()["model"];
  GbdtModel model;
  std::string error;
  const auto rejects = [&](const nlohmann::json& json) {
    return !GbdtModel::Parse(json.dump(), &model, &error);
  };
  EXPECT_TRUE(rejects(nlohmann::json::object()));
  nlohmann::json bad = good;
  bad["feature_set"] = "f0";
  EXPECT_TRUE(rejects(bad));
  EXPECT_NE(error.find("feature set"), std::string::npos);
  bad = good;
  bad["features"][3] = "renamed";
  EXPECT_TRUE(rejects(bad));
  bad = good;
  bad["trees"][0]["left"][0] = 0;  // Points back at itself: a loop.
  EXPECT_TRUE(rejects(bad));
  bad = good;
  bad["trees"][0]["feature"][0] = 1000;
  EXPECT_TRUE(rejects(bad));
  bad = good;
  bad["trees"][0]["value"].erase(0);  // Array sizes differ.
  EXPECT_TRUE(rejects(bad));
  EXPECT_FALSE(GbdtModel::Load("/nonexistent/model.json", &model, &error));
}

TEST(FeaturesTest, ExtractsTheVector) {
  HttpRequest request;
  request.method = "GET";
  request.headers = {
      {"user-agent",
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
       "like Gecko) Chrome/141.0.0.0 Safari/537.36"},
      {"accept", "text/html"},
      {"sec-fetch-mode", "navigate"},
      {"sec-ch-ua", R"("Chromium";v="141")"},
      {"cookie", "a=1"}};
  const std::vector<std::string> reasons = {"missing_accept_language",
                                            "behavior_regular_timing"};
  FeatureInput input;
  input.request = &request;
  input.path = "/catalog?page=2";
  input.ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
  input.http2 = true;
  input.offered_h2 = true;
  input.tcp_initial_ttl = 128;
  input.reasons = reasons;
  const auto f = ExtractFeatures(input);
  const auto at = [&f](std::string_view name) {
    for (std::size_t i = 0; i < kFeatureCount; ++i) {
      if (kFeatureNames[i] == name) return f[i];
    }
    ADD_FAILURE() << name;
    return -1.0F;
  };
  EXPECT_EQ(at("http2"), 1);
  EXPECT_EQ(at("header_count"), 5);
  EXPECT_EQ(at("has_cookie"), 1);
  EXPECT_EQ(at("has_accept_language"), 0);
  EXPECT_EQ(at("has_query"), 1);
  EXPECT_EQ(at("engine_chromium"), 1);
  EXPECT_EQ(at("engine_none"), 0);
  EXPECT_EQ(at("tls13"), 1);
  EXPECT_EQ(at("tls_ciphers"), 15);
  EXPECT_EQ(at("tls_extensions"), 16);
  EXPECT_EQ(at("alpn_h2"), 1);
  EXPECT_EQ(at("tls_sni"), 1);
  EXPECT_EQ(at("ttl_128"), 1);
  EXPECT_EQ(at("ttl_unknown"), 0);
  EXPECT_EQ(at("navigation"), 1);
  EXPECT_EQ(at("sig_missing_accept_language"), 1);
  EXPECT_EQ(at("sig_behavior_regular_timing"), 1);
  EXPECT_EQ(at("sig_ua_tls_mismatch"), 0);

  // No TLS (plain): JA4 parts are zero.
  input.ja4 = "";
  input.tcp_initial_ttl = 0;
  const auto plain = ExtractFeatures(input);
  EXPECT_EQ(plain[17], 0);  // tls13
  EXPECT_EQ(plain[18], 0);  // tls_ciphers
  EXPECT_EQ(plain[24], 1);  // ttl_unknown
}

TEST(ModelConfigTest, ParsesModel) {
  Config config;
  std::string error;
  EXPECT_TRUE(config.model_log_features);
  ASSERT_TRUE(
      ParseConfig("model: {file: /etc/bot-shield/model.json, threshold: 0.9, "
                  "log_features: false}\n",
                  &config, &error))
      << error;
  EXPECT_EQ(config.model_file, "/etc/bot-shield/model.json");
  EXPECT_DOUBLE_EQ(config.model_threshold, 0.9);
  EXPECT_FALSE(config.model_log_features);
  Config bad;
  EXPECT_FALSE(ParseConfig("model: {threshold: 1}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("model: {onnx: x}\n", &bad, &error));
}

}  // namespace
}  // namespace bot_shield
