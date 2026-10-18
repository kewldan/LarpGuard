#ifndef BOT_SHIELD_SCORE_RULES_H_
#define BOT_SHIELD_SCORE_RULES_H_

#include <asio/ip/address.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fp/http_request.h"
#include "score/policy.h"

namespace bot_shield {

// Everything a rule condition can read about one request.
struct RuleContext {
  const HttpRequest* request = nullptr;
  asio::ip::address ip;
  std::string_view host;  // Normalized, no port.
  std::string_view path;  // Without the query string.
  std::string_view sni;
  std::string_view alpn;
  std::string_view ja4;
  std::string_view h2_fingerprint;
  std::string_view pseudo_order;
  std::string_view header_fp;
  std::string_view tcp_fingerprint;
  std::string_view ua_family;
  std::string_view ua_engine;
  std::string_view ua_os;
  std::string_view ua_tool;
  int64_t score = 0;
  std::string_view bot_class;
  const std::vector<std::string>* reasons = nullptr;
};

// A compiled boolean condition (see docs/architecture.md, "Правила").
// Grammar:
//   expr    := and ("or" and)*
//   and     := not ("and" not)*
//   not     := "not" not | compare
//   compare := operand (("==" | "!=" | "<" | "<=" | ">" | ">=" | "~" | "in")
//                       operand)?
//   operand := string | integer | "true" | "false" | list | field
//            | function "(" string ")" | "(" expr ")"
// Types (string, int, bool, list) are checked when compiling.
class Condition {
 public:
  struct Node;

  // Compiles `text`; on failure returns nullptr and sets `error`.
  static std::unique_ptr<Condition> Compile(std::string_view text,
                                            std::string* error);
  ~Condition();

  Condition(const Condition&) = delete;
  Condition& operator=(const Condition&) = delete;

  bool Evaluate(const RuleContext& context) const;

 private:
  explicit Condition(std::unique_ptr<Node> root);

  std::unique_ptr<Node> root_;
};

// A rule as written in the configuration.
struct RuleSpec {
  std::string name;
  std::string when;
  std::string action;  // "allow", "block" or "score".
  int score = 0;       // For "score".
};

// Ordered rules. All "score" rules adjust the score first; then the first
// matching "allow"/"block" rule (which sees the adjusted score and class)
// overrides the action of the class.
class RuleSet {
 public:
  static bool Compile(const std::vector<RuleSpec>& specs, RuleSet* rules,
                      std::string* error);

  bool empty() const { return rules_.empty(); }

  // Score rules only; evaluates against `context.score` as given.
  int ScoreDelta(const RuleContext& context,
                 std::vector<std::string>* matched) const;
  // Allow/block rules; first match wins.
  std::optional<Action> Decide(const RuleContext& context,
                               std::vector<std::string>* matched) const;

 private:
  struct Rule {
    std::string name;
    enum class Kind { kAllow, kBlock, kScore } kind = Kind::kScore;
    int score = 0;
    std::shared_ptr<const Condition> condition;
  };

  std::vector<Rule> rules_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_SCORE_RULES_H_
