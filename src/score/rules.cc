#include "score/rules.h"

#include <algorithm>
#include <asio/ip/address.hpp>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/network.h"
#include "fp/library.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

enum class Type { kString, kInt, kBool, kList };

std::string_view TypeName(Type type) {
  switch (type) {
    case Type::kString:
      return "string";
    case Type::kInt:
      return "int";
    case Type::kBool:
      return "bool";
    case Type::kList:
      return "list";
  }
  return "?";
}

enum class Field {
  kHost,
  kMethod,
  kPath,
  kHttpVersion,
  kSni,
  kAlpn,
  kJa4,
  kH2Fingerprint,
  kPseudoOrder,
  kHeaderFp,
  kTcpFingerprint,
  kUserAgent,
  kUaFamily,
  kUaEngine,
  kUaOs,
  kUaTool,
  kScore,
  kClass,
  kReasons,
};

struct FieldInfo {
  std::string_view name;
  Field field;
  Type type;
};

constexpr FieldInfo kFields[] = {
    {"host", Field::kHost, Type::kString},
    {"method", Field::kMethod, Type::kString},
    {"path", Field::kPath, Type::kString},
    {"http_version", Field::kHttpVersion, Type::kString},
    {"sni", Field::kSni, Type::kString},
    {"alpn", Field::kAlpn, Type::kString},
    {"ja4", Field::kJa4, Type::kString},
    {"h2_fp", Field::kH2Fingerprint, Type::kString},
    {"pseudo_order", Field::kPseudoOrder, Type::kString},
    {"header_fp", Field::kHeaderFp, Type::kString},
    {"tcp_fp", Field::kTcpFingerprint, Type::kString},
    {"user_agent", Field::kUserAgent, Type::kString},
    {"ua_family", Field::kUaFamily, Type::kString},
    {"ua_engine", Field::kUaEngine, Type::kString},
    {"ua_os", Field::kUaOs, Type::kString},
    {"ua_tool", Field::kUaTool, Type::kString},
    {"score", Field::kScore, Type::kInt},
    {"class", Field::kClass, Type::kString},
    {"reasons", Field::kReasons, Type::kList},
};

enum class NodeKind {
  kLiteral,
  kField,
  kHeader,
  kHasHeader,
  kCidr,
  kNot,
  kAnd,
  kOr,
  kCompare,
  kGlob,
  kIn,
};

enum class CompareOp { kEq, kNe, kLt, kLe, kGt, kGe };

struct Value {
  Type type = Type::kBool;
  bool flag = false;
  int64_t number = 0;
  std::string_view text;
  const std::vector<std::string>* list = nullptr;
};

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

}  // namespace

struct Condition::Node {
  NodeKind kind = NodeKind::kLiteral;
  Type type = Type::kBool;
  // Literals.
  std::string text;
  int64_t number = 0;
  bool flag = false;
  std::vector<std::string> list;
  // Fields and comparisons.
  Field field = Field::kHost;
  CompareOp op = CompareOp::kEq;
  // cidr().
  Network network;
  std::unique_ptr<Node> left;
  std::unique_ptr<Node> right;
};

namespace {

using Node = Condition::Node;

// --- Lexer -------------------------------------------------------------------

enum class TokenKind {
  kString,
  kInt,
  kIdent,
  kOp,
  kLParen,
  kRParen,
  kLBracket,
  kRBracket,
  kComma,
  kEnd,
};

struct Token {
  TokenKind kind = TokenKind::kEnd;
  std::string text;
  int64_t number = 0;
  std::size_t position = 0;
};

class Lexer {
 public:
  explicit Lexer(std::string_view input) : input_(input) {}

  bool Tokenize(std::vector<Token>* tokens, std::string* error) {
    while (true) {
      while (pos_ < input_.size() &&
             std::isspace(static_cast<unsigned char>(input_[pos_])) != 0) {
        ++pos_;
      }
      Token token;
      token.position = pos_ + 1;
      if (pos_ >= input_.size()) {
        tokens->push_back(token);
        return true;
      }
      const char c = input_[pos_];
      if (c == '"') {
        if (!ReadString(&token, error)) return false;
      } else if (std::isdigit(static_cast<unsigned char>(c)) != 0 ||
                 (c == '-' && pos_ + 1 < input_.size() &&
                  std::isdigit(static_cast<unsigned char>(input_[pos_ + 1])) !=
                      0)) {
        const std::size_t start = pos_++;
        while (pos_ < input_.size() &&
               std::isdigit(static_cast<unsigned char>(input_[pos_])) != 0) {
          ++pos_;
        }
        token.kind = TokenKind::kInt;
        const std::string_view digits = input_.substr(start, pos_ - start);
        const auto [ptr, ec] = std::from_chars(
            digits.data(), digits.data() + digits.size(), token.number);
        if (ec != std::errc()) {
          *error = std::format("col {}: bad number", token.position);
          return false;
        }
      } else if (std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_') {
        const std::size_t start = pos_;
        while (pos_ < input_.size() &&
               (std::isalnum(static_cast<unsigned char>(input_[pos_])) != 0 ||
                input_[pos_] == '_')) {
          ++pos_;
        }
        token.kind = TokenKind::kIdent;
        token.text = std::string(input_.substr(start, pos_ - start));
      } else if (!ReadPunctuation(&token)) {
        *error = std::format("col {}: unexpected '{}'", token.position, c);
        return false;
      }
      tokens->push_back(std::move(token));
    }
  }

 private:
  bool ReadString(Token* token, std::string* error) {
    ++pos_;  // Opening quote.
    token->kind = TokenKind::kString;
    while (pos_ < input_.size() && input_[pos_] != '"') {
      if (input_[pos_] == '\\' && pos_ + 1 < input_.size()) ++pos_;
      token->text.push_back(input_[pos_++]);
    }
    if (pos_ >= input_.size()) {
      *error = std::format("col {}: unterminated string", token->position);
      return false;
    }
    ++pos_;  // Closing quote.
    return true;
  }

  bool ReadPunctuation(Token* token) {
    static constexpr std::string_view kTwoChar[] = {"==", "!=", "<=", ">="};
    for (std::string_view op : kTwoChar) {
      if (input_.substr(pos_).starts_with(op)) {
        token->kind = TokenKind::kOp;
        token->text = std::string(op);
        pos_ += 2;
        return true;
      }
    }
    const char c = input_[pos_];
    switch (c) {
      case '<':
      case '>':
      case '~':
        token->kind = TokenKind::kOp;
        token->text = std::string(1, c);
        break;
      case '(':
        token->kind = TokenKind::kLParen;
        break;
      case ')':
        token->kind = TokenKind::kRParen;
        break;
      case '[':
        token->kind = TokenKind::kLBracket;
        break;
      case ']':
        token->kind = TokenKind::kRBracket;
        break;
      case ',':
        token->kind = TokenKind::kComma;
        break;
      default:
        return false;
    }
    ++pos_;
    return true;
  }

  std::string_view input_;
  std::size_t pos_ = 0;
};

// --- Parser ------------------------------------------------------------------

class Parser {
 public:
  explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

  std::unique_ptr<Node> ParseAll(std::string* error) {
    auto root = ParseOr(error);
    if (!root) return nullptr;
    if (Peek().kind != TokenKind::kEnd) {
      return Fail(error, "unexpected trailing input");
    }
    if (root->type != Type::kBool) {
      return Fail(error, std::format("condition must be bool, not {}",
                                     TypeName(root->type)));
    }
    return root;
  }

 private:
  const Token& Peek() const { return tokens_[index_]; }
  const Token& Next() { return tokens_[index_++]; }
  bool IsKeyword(std::string_view word) const {
    return Peek().kind == TokenKind::kIdent && Peek().text == word;
  }

  std::unique_ptr<Node> Fail(std::string* error, std::string_view message) {
    *error = std::format("col {}: {}", Peek().position, message);
    return nullptr;
  }

  std::unique_ptr<Node> Logical(NodeKind kind, std::unique_ptr<Node> left,
                                std::unique_ptr<Node> right,
                                std::string* error) {
    if (left->type != Type::kBool || right->type != Type::kBool) {
      return Fail(error, "and/or need bool operands");
    }
    auto node = std::make_unique<Node>();
    node->kind = kind;
    node->type = Type::kBool;
    node->left = std::move(left);
    node->right = std::move(right);
    return node;
  }

  std::unique_ptr<Node> ParseOr(std::string* error) {
    auto left = ParseAnd(error);
    while (left && IsKeyword("or")) {
      Next();
      auto right = ParseAnd(error);
      if (!right) return nullptr;
      left = Logical(NodeKind::kOr, std::move(left), std::move(right), error);
    }
    return left;
  }

  std::unique_ptr<Node> ParseAnd(std::string* error) {
    auto left = ParseNot(error);
    while (left && IsKeyword("and")) {
      Next();
      auto right = ParseNot(error);
      if (!right) return nullptr;
      left = Logical(NodeKind::kAnd, std::move(left), std::move(right), error);
    }
    return left;
  }

  std::unique_ptr<Node> ParseNot(std::string* error) {
    if (!IsKeyword("not")) return ParseCompare(error);
    Next();
    auto operand = ParseNot(error);
    if (!operand) return nullptr;
    if (operand->type != Type::kBool) return Fail(error, "not needs a bool");
    auto node = std::make_unique<Node>();
    node->kind = NodeKind::kNot;
    node->type = Type::kBool;
    node->left = std::move(operand);
    return node;
  }

  std::unique_ptr<Node> ParseCompare(std::string* error) {
    auto left = ParseOperand(error);
    if (!left) return nullptr;
    const Token& token = Peek();
    const bool is_in = IsKeyword("in");
    if (token.kind != TokenKind::kOp && !is_in) return left;
    const std::string op = is_in ? "in" : token.text;
    Next();
    auto right = ParseOperand(error);
    if (!right) return nullptr;

    auto node = std::make_unique<Node>();
    node->type = Type::kBool;
    if (op == "in") {
      if (left->type != Type::kString || right->type != Type::kList) {
        return Fail(error, "'in' needs a string and a list");
      }
      node->kind = NodeKind::kIn;
    } else if (op == "~") {
      if (left->type != Type::kString || right->type != Type::kString) {
        return Fail(error, "'~' needs two strings");
      }
      node->kind = NodeKind::kGlob;
    } else {
      node->kind = NodeKind::kCompare;
      if (op == "==" || op == "!=") {
        node->op = op == "==" ? CompareOp::kEq : CompareOp::kNe;
        if (left->type != right->type || left->type == Type::kList) {
          return Fail(error,
                      std::format("cannot compare {} with {}",
                                  TypeName(left->type), TypeName(right->type)));
        }
      } else {
        node->op = op == "<"    ? CompareOp::kLt
                   : op == "<=" ? CompareOp::kLe
                   : op == ">"  ? CompareOp::kGt
                                : CompareOp::kGe;
        if (left->type != Type::kInt || right->type != Type::kInt) {
          return Fail(error, std::format("'{}' needs two ints", op));
        }
      }
    }
    node->left = std::move(left);
    node->right = std::move(right);
    return node;
  }

  std::unique_ptr<Node> ParseOperand(std::string* error) {
    const Token& token = Peek();
    auto node = std::make_unique<Node>();
    switch (token.kind) {
      case TokenKind::kString:
        node->kind = NodeKind::kLiteral;
        node->type = Type::kString;
        node->text = Next().text;
        return node;
      case TokenKind::kInt:
        node->kind = NodeKind::kLiteral;
        node->type = Type::kInt;
        node->number = Next().number;
        return node;
      case TokenKind::kLParen: {
        Next();
        auto inner = ParseOr(error);
        if (!inner) return nullptr;
        if (Peek().kind != TokenKind::kRParen) {
          return Fail(error, "expected ')'");
        }
        Next();
        return inner;
      }
      case TokenKind::kLBracket:
        return ParseList(error);
      case TokenKind::kIdent:
        return ParseIdentifier(error);
      default:
        return Fail(error, "expected a value");
    }
  }

  std::unique_ptr<Node> ParseList(std::string* error) {
    Next();  // '['
    auto node = std::make_unique<Node>();
    node->kind = NodeKind::kLiteral;
    node->type = Type::kList;
    while (Peek().kind != TokenKind::kRBracket) {
      if (Peek().kind != TokenKind::kString) {
        return Fail(error, "lists hold strings");
      }
      node->list.push_back(Next().text);
      if (Peek().kind == TokenKind::kComma) {
        Next();
      } else if (Peek().kind != TokenKind::kRBracket) {
        return Fail(error, "expected ',' or ']'");
      }
    }
    Next();  // ']'
    return node;
  }

  std::unique_ptr<Node> ParseIdentifier(std::string* error) {
    const std::string name = Peek().text;
    auto node = std::make_unique<Node>();
    if (name == "true" || name == "false") {
      Next();
      node->kind = NodeKind::kLiteral;
      node->type = Type::kBool;
      node->flag = name == "true";
      return node;
    }
    if (name == "header" || name == "has_header" || name == "cidr") {
      Next();
      if (Peek().kind != TokenKind::kLParen) return Fail(error, "expected '('");
      Next();
      if (Peek().kind != TokenKind::kString) {
        return Fail(error, std::format("{}() takes a string literal", name));
      }
      const std::string argument = Next().text;
      if (Peek().kind != TokenKind::kRParen) return Fail(error, "expected ')'");
      Next();
      if (name == "cidr") {
        node->kind = NodeKind::kCidr;
        node->type = Type::kBool;
        if (!Network::Parse(argument, &node->network)) {
          return Fail(error, std::format("bad network '{}'", argument));
        }
      } else {
        node->kind =
            name == "header" ? NodeKind::kHeader : NodeKind::kHasHeader;
        node->type = name == "header" ? Type::kString : Type::kBool;
        node->text = Lowercase(argument);
      }
      return node;
    }
    for (const FieldInfo& info : kFields) {
      if (info.name == name) {
        Next();
        node->kind = NodeKind::kField;
        node->type = info.type;
        node->field = info.field;
        return node;
      }
    }
    return Fail(error, std::format("unknown name '{}'", name));
  }

  std::vector<Token> tokens_;
  std::size_t index_ = 0;
};

// --- Evaluation --------------------------------------------------------------

Value FieldValue(Field field, const RuleContext& context) {
  Value value;
  value.type = Type::kString;
  switch (field) {
    case Field::kHost:
      value.text = context.host;
      break;
    case Field::kMethod:
      value.text = context.request->method;
      break;
    case Field::kPath:
      value.text = context.path;
      break;
    case Field::kHttpVersion:
      value.text = context.request->version;
      break;
    case Field::kSni:
      value.text = context.sni;
      break;
    case Field::kAlpn:
      value.text = context.alpn;
      break;
    case Field::kJa4:
      value.text = context.ja4;
      break;
    case Field::kH2Fingerprint:
      value.text = context.h2_fingerprint;
      break;
    case Field::kPseudoOrder:
      value.text = context.pseudo_order;
      break;
    case Field::kHeaderFp:
      value.text = context.header_fp;
      break;
    case Field::kTcpFingerprint:
      value.text = context.tcp_fingerprint;
      break;
    case Field::kUserAgent:
      value.text = context.request->Header("user-agent");
      break;
    case Field::kUaFamily:
      value.text = context.ua_family;
      break;
    case Field::kUaEngine:
      value.text = context.ua_engine;
      break;
    case Field::kUaOs:
      value.text = context.ua_os;
      break;
    case Field::kUaTool:
      value.text = context.ua_tool;
      break;
    case Field::kScore:
      value.type = Type::kInt;
      value.number = context.score;
      break;
    case Field::kClass:
      value.text = context.bot_class;
      break;
    case Field::kReasons:
      value.type = Type::kList;
      value.list = context.reasons;
      break;
  }
  return value;
}

Value Evaluate(const Node& node, const RuleContext& context) {
  Value value;
  value.type = node.type;
  switch (node.kind) {
    case NodeKind::kLiteral:
      value.flag = node.flag;
      value.number = node.number;
      value.text = node.text;
      value.list = &node.list;
      return value;
    case NodeKind::kField:
      return FieldValue(node.field, context);
    case NodeKind::kHeader:
      value.text = context.request->Header(node.text);
      return value;
    case NodeKind::kHasHeader:
      value.flag = context.request->HasHeader(node.text);
      return value;
    case NodeKind::kCidr:
      value.flag = node.network.Contains(context.ip);
      return value;
    case NodeKind::kNot:
      value.flag = !Evaluate(*node.left, context).flag;
      return value;
    case NodeKind::kAnd:
      value.flag = Evaluate(*node.left, context).flag &&
                   Evaluate(*node.right, context).flag;
      return value;
    case NodeKind::kOr:
      value.flag = Evaluate(*node.left, context).flag ||
                   Evaluate(*node.right, context).flag;
      return value;
    case NodeKind::kGlob:
      value.flag = GlobMatch(Evaluate(*node.right, context).text,
                             Evaluate(*node.left, context).text);
      return value;
    case NodeKind::kIn: {
      const Value needle = Evaluate(*node.left, context);
      const Value haystack = Evaluate(*node.right, context);
      value.flag = haystack.list != nullptr &&
                   std::ranges::find(*haystack.list, needle.text) !=
                       haystack.list->end();
      return value;
    }
    case NodeKind::kCompare: {
      const Value left = Evaluate(*node.left, context);
      const Value right = Evaluate(*node.right, context);
      int order = 0;
      if (left.type == Type::kInt) {
        order = left.number < right.number ? -1 : (left.number > right.number);
      } else if (left.type == Type::kBool) {
        order = left.flag == right.flag ? 0 : 1;
      } else {
        order = left.text.compare(right.text);
      }
      switch (node.op) {
        case CompareOp::kEq:
          value.flag = order == 0;
          break;
        case CompareOp::kNe:
          value.flag = order != 0;
          break;
        case CompareOp::kLt:
          value.flag = order < 0;
          break;
        case CompareOp::kLe:
          value.flag = order <= 0;
          break;
        case CompareOp::kGt:
          value.flag = order > 0;
          break;
        case CompareOp::kGe:
          value.flag = order >= 0;
          break;
      }
      return value;
    }
  }
  return value;
}

}  // namespace

Condition::Condition(std::unique_ptr<Node> root) : root_(std::move(root)) {}

Condition::~Condition() = default;

std::unique_ptr<Condition> Condition::Compile(std::string_view text,
                                              std::string* error) {
  std::vector<Token> tokens;
  if (!Lexer(text).Tokenize(&tokens, error)) return nullptr;
  Parser parser(std::move(tokens));
  std::unique_ptr<Node> root = parser.ParseAll(error);
  if (!root) return nullptr;
  return std::unique_ptr<Condition>(new Condition(std::move(root)));
}

bool Condition::Evaluate(const RuleContext& context) const {
  return bot_shield::Evaluate(*root_, context).flag;
}

bool RuleSet::Compile(const std::vector<RuleSpec>& specs, RuleSet* rules,
                      std::string* error) {
  RuleSet out;
  std::set<std::string> names;
  for (const RuleSpec& spec : specs) {
    if (spec.name.empty() || !names.insert(spec.name).second) {
      *error = std::format("rule '{}': names must be unique and non-empty",
                           spec.name);
      return false;
    }
    Rule rule;
    rule.name = spec.name;
    Action action = Action::kAllow;
    if (ParseAction(spec.action, &action)) {
      rule.action = action;
    } else if (spec.action == "score") {
      if (spec.score == 0) {
        *error = std::format("rule '{}': action score needs a non-zero score",
                             spec.name);
        return false;
      }
      rule.score = spec.score;
    } else {
      *error = std::format(
          "rule '{}': action must be allow, challenge, block, tarpit, decoy, "
          "throttle or score",
          spec.name);
      return false;
    }
    std::string condition_error;
    rule.condition = Condition::Compile(spec.when, &condition_error);
    if (!rule.condition) {
      *error = std::format("rule '{}': {}", spec.name, condition_error);
      return false;
    }
    out.rules_.push_back(std::move(rule));
  }
  *rules = std::move(out);
  return true;
}

int RuleSet::ScoreDelta(const RuleContext& context,
                        std::vector<std::string>* matched) const {
  int delta = 0;
  for (const Rule& rule : rules_) {
    if (rule.action) continue;
    if (rule.condition->Evaluate(context)) {
      delta += rule.score;
      matched->push_back(rule.name);
    }
  }
  return delta;
}

std::optional<Action> RuleSet::Decide(const RuleContext& context,
                                      std::vector<std::string>* matched) const {
  for (const Rule& rule : rules_) {
    if (!rule.action) continue;
    if (rule.condition->Evaluate(context)) {
      matched->push_back(rule.name);
      return rule.action;
    }
  }
  return std::nullopt;
}

}  // namespace bot_shield
