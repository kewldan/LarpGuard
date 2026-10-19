#include "common/structured_fields.h"

#include <openssl/base64.h>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace bot_shield::sf {
namespace {

bool IsAlpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool IsDigit(char c) { return c >= '0' && c <= '9'; }
bool IsLcAlpha(char c) { return c >= 'a' && c <= 'z'; }

// tchar from RFC 9110, plus ':' and '/' allowed in tokens.
bool IsTokenChar(char c) {
  if (IsAlpha(c) || IsDigit(c)) return true;
  switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
    case ':':
    case '/':
      return true;
    default:
      return false;
  }
}

class Parser {
 public:
  explicit Parser(std::string_view text) : text_(text) {}

  bool AtEnd() const { return pos_ >= text_.size(); }
  bool Consume(char c) {
    if (Peek() != c) return false;
    ++pos_;
    return true;
  }
  char Peek() const { return AtEnd() ? '\0' : text_[pos_]; }
  void SkipSp() {
    while (Peek() == ' ') ++pos_;
  }
  void SkipOws() {
    while (Peek() == ' ' || Peek() == '\t') ++pos_;
  }

  std::optional<std::string> Key() {
    const char first = Peek();
    if (!IsLcAlpha(first) && first != '*') return std::nullopt;
    std::string key;
    while (!AtEnd()) {
      const char c = Peek();
      if (!IsLcAlpha(c) && !IsDigit(c) && c != '_' && c != '-' && c != '.' &&
          c != '*') {
        break;
      }
      key.push_back(c);
      ++pos_;
    }
    return key;
  }

  std::optional<BareItem> Bare() {
    const char c = Peek();
    if (c == '-' || IsDigit(c)) return Number();
    if (c == '"') return String();
    if (c == '*' || IsAlpha(c)) return Token();
    if (c == ':') return Bytes();
    if (c == '?') return Boolean();
    return std::nullopt;
  }

  std::optional<Parameters> Params() {
    Parameters params;
    while (Peek() == ';') {
      ++pos_;
      SkipSp();
      std::optional<std::string> key = Key();
      if (!key) return std::nullopt;
      BareItem value;
      value.type = BareItem::Type::kBoolean;
      value.boolean = true;
      if (Peek() == '=') {
        ++pos_;
        std::optional<BareItem> parsed = Bare();
        if (!parsed) return std::nullopt;
        value = std::move(*parsed);
      }
      bool replaced = false;
      for (auto& [existing, existing_value] : params) {
        if (existing == *key) {
          existing_value = value;
          replaced = true;
        }
      }
      if (!replaced) params.emplace_back(std::move(*key), std::move(value));
    }
    return params;
  }

  std::optional<Item> ParseItemWithParams() {
    std::optional<BareItem> bare = Bare();
    if (!bare) return std::nullopt;
    std::optional<Parameters> params = Params();
    if (!params) return std::nullopt;
    return Item{std::move(*bare), std::move(*params)};
  }

  std::optional<Member> ParseMember() {
    Member member;
    if (Peek() == '(') {
      ++pos_;
      member.is_inner_list = true;
      while (true) {
        SkipSp();
        if (Peek() == ')') {
          ++pos_;
          break;
        }
        std::optional<Item> item = ParseItemWithParams();
        if (!item) return std::nullopt;
        member.inner_list.items.push_back(std::move(*item));
        if (Peek() != ' ' && Peek() != ')') return std::nullopt;
      }
      std::optional<Parameters> params = Params();
      if (!params) return std::nullopt;
      member.inner_list.params = std::move(*params);
      return member;
    }
    std::optional<Item> item = ParseItemWithParams();
    if (!item) return std::nullopt;
    member.item = std::move(*item);
    return member;
  }

 private:
  std::optional<BareItem> Number() {
    const std::size_t start = pos_;
    if (Peek() == '-') ++pos_;
    bool decimal = false;
    while (!AtEnd() && (IsDigit(Peek()) || (Peek() == '.' && !decimal))) {
      if (Peek() == '.') decimal = true;
      ++pos_;
    }
    const std::string_view number = text_.substr(start, pos_ - start);
    BareItem item;
    if (decimal) {
      item.type = BareItem::Type::kDecimal;
      item.text = std::string(number);
      return item;
    }
    if (number.size() > 16) return std::nullopt;
    item.type = BareItem::Type::kInteger;
    const auto [end, error] = std::from_chars(
        number.data(), number.data() + number.size(), item.integer);
    if (error != std::errc() || end != number.data() + number.size()) {
      return std::nullopt;
    }
    return item;
  }

  std::optional<BareItem> String() {
    ++pos_;  // Opening quote.
    BareItem item;
    item.type = BareItem::Type::kString;
    while (!AtEnd()) {
      const char c = text_[pos_++];
      if (c == '\\') {
        if (AtEnd()) return std::nullopt;
        const char next = text_[pos_++];
        if (next != '"' && next != '\\') return std::nullopt;
        item.text.push_back(next);
      } else if (c == '"') {
        return item;
      } else if (c < 0x20 || c == 0x7f) {
        return std::nullopt;
      } else {
        item.text.push_back(c);
      }
    }
    return std::nullopt;
  }

  std::optional<BareItem> Token() {
    BareItem item;
    item.type = BareItem::Type::kToken;
    while (!AtEnd() && IsTokenChar(Peek())) item.text.push_back(text_[pos_++]);
    return item;
  }

  std::optional<BareItem> Bytes() {
    ++pos_;
    const std::size_t end = text_.find(':', pos_);
    if (end == std::string_view::npos) return std::nullopt;
    const std::string_view encoded = text_.substr(pos_, end - pos_);
    pos_ = end + 1;
    BareItem item;
    item.type = BareItem::Type::kBytes;
    std::size_t max_size = 0;
    if (!EVP_DecodedLength(&max_size, encoded.size())) return std::nullopt;
    item.text.resize(max_size);
    std::size_t size = 0;
    if (!EVP_DecodeBase64(
            reinterpret_cast<uint8_t*>(item.text.data()), &size, max_size,
            reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size())) {
      return std::nullopt;
    }
    item.text.resize(size);
    return item;
  }

  std::optional<BareItem> Boolean() {
    ++pos_;
    BareItem item;
    item.type = BareItem::Type::kBoolean;
    if (Peek() == '1') {
      item.boolean = true;
    } else if (Peek() != '0') {
      return std::nullopt;
    }
    ++pos_;
    return item;
  }

  std::string_view text_;
  std::size_t pos_ = 0;
};

std::string_view Trim(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1);
  }
  return text;
}

const BareItem* FindParam(const Parameters& params, std::string_view key) {
  for (const auto& [name, value] : params) {
    if (name == key) return &value;
  }
  return nullptr;
}

}  // namespace

const BareItem* Item::Param(std::string_view key) const {
  return FindParam(params, key);
}

const BareItem* InnerList::Param(std::string_view key) const {
  return FindParam(params, key);
}

std::optional<Dictionary> ParseDictionary(std::string_view text) {
  Parser parser(Trim(text));
  Dictionary dictionary;
  while (!parser.AtEnd()) {
    std::optional<std::string> key = parser.Key();
    if (!key) return std::nullopt;
    Member member;
    if (parser.Consume('=')) {
      std::optional<Member> parsed = parser.ParseMember();
      if (!parsed) return std::nullopt;
      member = std::move(*parsed);
    } else {
      member.item.value.type = BareItem::Type::kBoolean;
      member.item.value.boolean = true;
      std::optional<Parameters> params = parser.Params();
      if (!params) return std::nullopt;
      member.item.params = std::move(*params);
    }
    bool replaced = false;
    for (auto& [existing, existing_member] : dictionary) {
      if (existing == *key) {
        existing_member = member;
        replaced = true;
      }
    }
    if (!replaced) dictionary.emplace_back(std::move(*key), std::move(member));
    parser.SkipOws();
    if (parser.AtEnd()) break;
    if (!parser.Consume(',')) return std::nullopt;
    parser.SkipOws();
    if (parser.AtEnd()) return std::nullopt;  // Trailing comma.
  }
  return dictionary;
}

std::optional<Item> ParseItem(std::string_view text) {
  Parser parser(Trim(text));
  std::optional<Item> item = parser.ParseItemWithParams();
  if (!item || !parser.AtEnd()) return std::nullopt;
  return item;
}

std::string Serialize(const BareItem& item) {
  switch (item.type) {
    case BareItem::Type::kInteger:
      return std::to_string(item.integer);
    case BareItem::Type::kDecimal:
    case BareItem::Type::kToken:
      return item.text;
    case BareItem::Type::kString: {
      std::string out = "\"";
      for (const char c : item.text) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
      }
      out.push_back('"');
      return out;
    }
    case BareItem::Type::kBytes: {
      std::size_t size = 0;
      EVP_EncodedLength(&size, item.text.size());
      std::string out(size, '\0');
      const std::size_t written = EVP_EncodeBlock(
          reinterpret_cast<uint8_t*>(out.data()),
          reinterpret_cast<const uint8_t*>(item.text.data()), item.text.size());
      out.resize(written);
      return ":" + out + ":";
    }
    case BareItem::Type::kBoolean:
      return item.boolean ? "?1" : "?0";
  }
  return {};
}

std::string Serialize(const Parameters& params) {
  std::string out;
  for (const auto& [key, value] : params) {
    out += ";" + key;
    if (value.type == BareItem::Type::kBoolean && value.boolean) continue;
    out += "=" + Serialize(value);
  }
  return out;
}

std::string Serialize(const Item& item) {
  return Serialize(item.value) + Serialize(item.params);
}

std::string Serialize(const InnerList& list) {
  std::string out = "(";
  for (std::size_t i = 0; i < list.items.size(); ++i) {
    if (i > 0) out.push_back(' ');
    out += Serialize(list.items[i]);
  }
  out += ')';
  out += Serialize(list.params);
  return out;
}

std::string Serialize(const Member& member) {
  return member.is_inner_list ? Serialize(member.inner_list)
                              : Serialize(member.item);
}

const Member* Find(const Dictionary& dictionary, std::string_view key) {
  for (const auto& [name, member] : dictionary) {
    if (name == key) return &member;
  }
  return nullptr;
}

}  // namespace bot_shield::sf
