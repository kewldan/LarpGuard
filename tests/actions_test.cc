#include "action/actions.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "config/config.h"
#include "score/policy.h"
#include "score/rules.h"

namespace bot_shield {
namespace {

TEST(DecoyTest, WatermarksBuiltInAndCustomTemplates) {
  const std::string mark = DecoyWatermark("secret", "local-1-1");
  EXPECT_EQ(mark.size(), 12U);
  EXPECT_EQ(mark, DecoyWatermark("secret", "local-1-1"));
  EXPECT_NE(mark, DecoyWatermark("secret", "local-1-2"));
  EXPECT_NE(mark, DecoyWatermark("other", "local-1-1"));

  const std::string html = RenderDecoy("", true, mark);
  EXPECT_TRUE(html.starts_with("<!doctype html>"));
  EXPECT_EQ(html.find("{{watermark}}"), std::string::npos);
  EXPECT_NE(html.find("sales-" + mark + "@"), std::string::npos);
  const std::string json = RenderDecoy("", false, mark);
  EXPECT_TRUE(json.starts_with("{\"items\""));
  EXPECT_NE(json.find(mark + "-02"), std::string::npos);
  EXPECT_EQ(RenderDecoy("a{{watermark}}b{{watermark}}", true, "W"), "aWbW");
  // A watermark containing the placeholder does not loop.
  EXPECT_EQ(RenderDecoy("{{watermark}}", true, "{{watermark}}"),
            "{{watermark}}");
}

TEST(DecoyTest, LabyrinthIsStableAndLeadsDeeper) {
  const std::string page = RenderLabyrinth("secret", "/docs/a", "W1");
  EXPECT_TRUE(page.starts_with("<!doctype html>"));
  EXPECT_NE(page.find(R"(content="noindex,nofollow")"), std::string::npos);
  EXPECT_NE(page.find("W1"), std::string::npos);
  // The same path always gives the same page (but for the watermark).
  EXPECT_EQ(page, RenderLabyrinth("secret", "/docs/a", "W1"));
  EXPECT_NE(page, RenderLabyrinth("secret", "/docs/b", "W1"));
  EXPECT_NE(page, RenderLabyrinth("other", "/docs/a", "W1"));
  // Twelve nofollow links to other paths on the same host.
  std::vector<std::string> links;
  for (std::size_t at = page.find("href=\""); at != std::string::npos;
       at = page.find("href=\"", at + 1)) {
    const std::size_t start = at + 6;
    links.push_back(page.substr(start, page.find('"', start) - start));
  }
  ASSERT_EQ(links.size(), 12U);
  for (const std::string& link : links) {
    EXPECT_TRUE(link.starts_with('/')) << link;
    EXPECT_EQ(link.find("//"), std::string::npos) << link;
  }
  EXPECT_NE(RenderLabyrinth("secret", links[0], "W1"), page);
  EXPECT_NE(kAiRobotsTxt.find("Disallow: /\n"), std::string_view::npos);
}

TEST(ActionsTest, ParsesNewActions) {
  Action action = Action::kAllow;
  ASSERT_TRUE(ParseAction("tarpit", &action));
  EXPECT_EQ(action, Action::kTarpit);
  ASSERT_TRUE(ParseAction("decoy", &action));
  EXPECT_EQ(ActionName(action), "decoy");

  RuleSet rules;
  std::string error;
  std::vector<RuleSpec> specs(2);
  specs[0].name = "slow";
  specs[0].when = R"(path ~ "/slow*")";
  specs[0].action = "tarpit";
  specs[1].name = "fake";
  specs[1].when = R"(path ~ "/fake*")";
  specs[1].action = "decoy";
  ASSERT_TRUE(RuleSet::Compile(specs, &rules, &error)) << error;
  specs[1].action = "nope";
  EXPECT_FALSE(RuleSet::Compile(specs, &rules, &error));
}

TEST(ActionsTest, ParsesConfig) {
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(
      "tarpit: {duration: 1m, interval: 2s, chunk: 8, max_active: 50}\n"
      "policy: {actions: {bot: tarpit, suspicious: decoy}}\n",
      &config, &error))
      << error;
  EXPECT_EQ(config.tarpit_duration, std::chrono::minutes(1));
  EXPECT_EQ(config.tarpit_interval, std::chrono::seconds(2));
  EXPECT_EQ(config.tarpit_chunk, 8U);
  EXPECT_EQ(config.tarpit_max_active, 50U);
  EXPECT_EQ(config.policy.bot_action, Action::kTarpit);
  EXPECT_EQ(config.policy.suspicious_action, Action::kDecoy);
  Config empty;
  EXPECT_TRUE(ParseConfig("decoy: {html_file: \"\", json_file: null}\n", &empty,
                          &error))
      << error;

  Config bad;
  EXPECT_FALSE(ParseConfig("tarpit: {interval: 1ms}\n", &bad, &error));
  EXPECT_FALSE(
      ParseConfig("tarpit: {duration: 1s, interval: 2s}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("tarpit: {chunk: 0}\n", &bad, &error));
  EXPECT_FALSE(
      ParseConfig("decoy: {html_file: /nonexistent.html}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("decoy: {xml_file: x}\n", &bad, &error));
}

}  // namespace
}  // namespace bot_shield
