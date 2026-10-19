#include "score/rules.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"
#include "score/policy.h"
#include "score/scorer.h"

namespace bot_shield {
namespace {

class RulesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    request_.version = "2";
    request_.method = "GET";
    request_.headers = {{"user-agent", "curl/8.7.1"}, {"x-monitor", "token"}};
    context_.request = &request_;
    context_.ip = asio::ip::make_address("203.0.113.7");
    context_.host = "shop.test";
    context_.path = "/admin/users";
    context_.ja4 = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac";
    context_.ua_tool = "curl";
    context_.score = 80;
    context_.bot_class = "bot";
    context_.reasons = &reasons_;
  }

  bool Eval(std::string_view text) {
    std::string error;
    auto condition = Condition::Compile(text, &error);
    EXPECT_NE(condition, nullptr) << text << ": " << error;
    return condition != nullptr && condition->Evaluate(context_);
  }

  static std::string CompileError(std::string_view text) {
    std::string error;
    auto condition = Condition::Compile(text, &error);
    EXPECT_EQ(condition, nullptr) << text;
    return error;
  }

  HttpRequest request_;
  std::vector<std::string> reasons_ = {"automation_user_agent",
                                       "ua_tls_mismatch"};
  RuleContext context_;
};

TEST_F(RulesTest, ComparisonsAndLogic) {
  EXPECT_TRUE(Eval(R"(host == "shop.test")"));
  EXPECT_FALSE(Eval(R"(host != "shop.test")"));
  EXPECT_TRUE(Eval("score >= 70 and score < 100"));
  EXPECT_TRUE(Eval("score > 79 and not (score <= 79)"));
  EXPECT_TRUE(Eval(R"(class == "human" or ua_tool == "curl")"));
  // not > and > or.
  EXPECT_TRUE(Eval(R"(host == "x" and false or true)"));
  EXPECT_FALSE(Eval(R"(not true or false)"));
  EXPECT_TRUE(Eval("true == true"));
  EXPECT_TRUE(Eval("-5 < 0"));
}

TEST_F(RulesTest, GlobInHeadersAndCidr) {
  EXPECT_TRUE(Eval(R"(path ~ "/admin*")"));
  EXPECT_TRUE(Eval(R"(ja4 ~ "t13d31*_e8f1e7e78f70_*")"));
  EXPECT_FALSE(Eval(R"(path ~ "/api/*")"));
  EXPECT_TRUE(Eval(R"(ua_tool in ["curl", "wget"])"));
  EXPECT_FALSE(Eval(R"(ua_tool in [])"));
  EXPECT_TRUE(Eval(R"("ua_tls_mismatch" in reasons)"));
  EXPECT_FALSE(Eval(R"("missing_client_hints" in reasons)"));
  EXPECT_TRUE(Eval(R"(header("X-Monitor") == "token")"));
  EXPECT_TRUE(Eval(R"(header("absent") == "")"));
  EXPECT_TRUE(Eval(R"(has_header("user-agent") and not has_header("cookie"))"));
  EXPECT_TRUE(Eval(R"(user_agent ~ "curl/*")"));
  EXPECT_TRUE(Eval(R"(cidr("203.0.113.0/24"))"));
  EXPECT_TRUE(Eval(R"(cidr("203.0.113.7"))"));
  EXPECT_FALSE(Eval(R"(cidr("198.51.100.0/24"))"));
  EXPECT_FALSE(Eval(R"(cidr("2001:db8::/32"))"));
  EXPECT_TRUE(Eval(R"(cidr("0.0.0.0/0"))"));
  context_.ip = asio::ip::make_address("::ffff:203.0.113.9");
  EXPECT_TRUE(Eval(R"(cidr("203.0.113.0/24"))"));
  context_.ip = asio::ip::make_address("2001:db8:1::5");
  EXPECT_TRUE(Eval(R"(cidr("2001:db8::/32"))"));
  EXPECT_FALSE(Eval(R"(cidr("0.0.0.0/0"))"));
  EXPECT_TRUE(Eval(R"(cidr("::/0"))"));
}

TEST_F(RulesTest, AsnAndSignedAgentFields) {
  context_.asn = 16509;
  context_.asn_org = "AMAZON-02";
  context_.asn_country = "US";
  context_.asn_hosting = true;
  context_.signed_agent = "chatgpt.com";
  EXPECT_TRUE(Eval("asn == 16509"));
  EXPECT_TRUE(Eval("asn_hosting and asn_country in [\"US\", \"DE\"]"));
  EXPECT_TRUE(Eval("asn_org ~ \"AMAZON*\""));
  EXPECT_TRUE(Eval("signed_agent == \"chatgpt.com\""));
  EXPECT_FALSE(Eval("not asn_hosting"));
  context_.asn_hosting = false;
  EXPECT_TRUE(Eval("asn_hosting == false"));
  std::string error;
  EXPECT_FALSE(Condition::Compile("asn == \"16509\"", &error));
}

TEST_F(RulesTest, StringEscapes) {
  context_.host = R"(a"b\c)";
  EXPECT_TRUE(Eval(R"(host == "a\"b\\c")"));
}

TEST_F(RulesTest, CompileErrors) {
  EXPECT_NE(CompileError("hots == \"a\"").find("unknown name 'hots'"),
            std::string::npos);
  EXPECT_NE(
      CompileError("score == \"80\"").find("cannot compare int with string"),
      std::string::npos);
  EXPECT_NE(CompileError("host < \"a\"").find("needs two ints"),
            std::string::npos);
  EXPECT_NE(CompileError("score ~ \"8*\"").find("two strings"),
            std::string::npos);
  EXPECT_NE(CompileError("host in \"abc\"").find("string and a list"),
            std::string::npos);
  EXPECT_NE(CompileError("host").find("must be bool"), std::string::npos);
  EXPECT_NE(CompileError("score and true").find("bool"), std::string::npos);
  EXPECT_NE(CompileError("(true").find("expected ')'"), std::string::npos);
  EXPECT_NE(CompileError("\"open").find("unterminated"), std::string::npos);
  EXPECT_NE(CompileError("true true").find("trailing"), std::string::npos);
  EXPECT_NE(CompileError("cidr(\"300.1.1.1/8\")").find("bad network"),
            std::string::npos);
  EXPECT_NE(CompileError("header(host) == \"\"").find("string literal"),
            std::string::npos);
  EXPECT_NE(CompileError("host == \"a\" & true").find("unexpected '&'"),
            std::string::npos);
  EXPECT_NE(CompileError("[1]").find("lists hold strings"), std::string::npos);
}

TEST_F(RulesTest, RuleSetOrderAndKinds) {
  RuleSet rules;
  std::string error;
  ASSERT_TRUE(RuleSet::Compile(
      {
          {"monitoring", R"(header("x-monitor") == "token")", "allow", 0},
          {"admin", R"(path ~ "/admin*")", "block", 0},
          {"trusted-net", R"(cidr("203.0.113.0/24"))", "score", -50},
          {"curl", R"(ua_tool == "curl")", "score", 10},
      },
      &rules, &error))
      << error;
  std::vector<std::string> matched;
  EXPECT_EQ(rules.ScoreDelta(context_, &matched), -40);
  EXPECT_EQ(matched, (std::vector<std::string>{"trusted-net", "curl"}));
  matched.clear();
  // First allow/block match wins.
  EXPECT_EQ(rules.Decide(context_, &matched), Action::kAllow);
  EXPECT_EQ(matched, std::vector<std::string>{"monitoring"});
  request_.headers.pop_back();
  matched.clear();
  EXPECT_EQ(rules.Decide(context_, &matched), Action::kBlock);
  context_.path = "/";
  EXPECT_EQ(rules.Decide(context_, &matched), std::nullopt);
}

TEST_F(RulesTest, RuleSetValidation) {
  RuleSet rules;
  std::string error;
  EXPECT_FALSE(RuleSet::Compile({{"", "true", "block", 0}}, &rules, &error));
  EXPECT_FALSE(RuleSet::Compile(
      {{"a", "true", "block", 0}, {"a", "true", "allow", 0}}, &rules, &error));
  EXPECT_FALSE(RuleSet::Compile({{"a", "true", "tag", 0}}, &rules, &error));
  EXPECT_FALSE(RuleSet::Compile({{"a", "true", "score", 0}}, &rules, &error));
  EXPECT_FALSE(RuleSet::Compile({{"a", "score", "block", 0}}, &rules, &error));
  EXPECT_NE(error.find("rule 'a'"), std::string::npos) << error;
}

TEST(PolicyOverrideTest, RulesOverrideClassActions) {
  PolicySettings settings;
  settings.enforce = true;
  const Policy policy(settings);
  Verdict bot;
  bot.bot_class = BotClass::kBot;
  EXPECT_EQ(policy.Decide(bot, "a", Action::kAllow).action, Action::kAllow);
  Verdict human;
  EXPECT_EQ(policy.Decide(human, "a", Action::kBlock).action, Action::kBlock);
  settings.enforce = false;
  const Policy shadow(settings);
  const PolicyDecision decision = shadow.Decide(human, "a", Action::kBlock);
  EXPECT_EQ(decision.action, Action::kAllow);
  EXPECT_EQ(decision.would_action, Action::kBlock);
}

}  // namespace
}  // namespace bot_shield
