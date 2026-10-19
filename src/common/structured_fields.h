#ifndef BOT_SHIELD_COMMON_STRUCTURED_FIELDS_H_
#define BOT_SHIELD_COMMON_STRUCTURED_FIELDS_H_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield::sf {

// Structured Field Values (RFC 8941), enough for HTTP Message Signatures:
// items, inner lists, parameters and dictionaries. Decimals are kept as
// their text.

struct BareItem {
  enum class Type { kInteger, kDecimal, kString, kToken, kBytes, kBoolean };
  Type type = Type::kToken;
  int64_t integer = 0;
  bool boolean = false;
  // String, token, decimal text, or the decoded bytes.
  std::string text;
};

using Parameters = std::vector<std::pair<std::string, BareItem>>;

struct Item {
  BareItem value;
  Parameters params;

  const BareItem* Param(std::string_view key) const;
};

struct InnerList {
  std::vector<Item> items;
  Parameters params;

  const BareItem* Param(std::string_view key) const;
};

// A dictionary or list member: an item or an inner list.
struct Member {
  bool is_inner_list = false;
  Item item;
  InnerList inner_list;
};

using Dictionary = std::vector<std::pair<std::string, Member>>;

std::optional<Dictionary> ParseDictionary(std::string_view text);
std::optional<Item> ParseItem(std::string_view text);

// Canonical serializations (RFC 8941 section 4.1).
std::string Serialize(const BareItem& item);
std::string Serialize(const Parameters& params);
std::string Serialize(const Item& item);
std::string Serialize(const InnerList& list);
std::string Serialize(const Member& member);

const Member* Find(const Dictionary& dictionary, std::string_view key);

}  // namespace bot_shield::sf

#endif  // BOT_SHIELD_COMMON_STRUCTURED_FIELDS_H_
