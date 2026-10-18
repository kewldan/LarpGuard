#ifndef BOT_SHIELD_COMMON_URL_H_
#define BOT_SHIELD_COMMON_URL_H_

#include <functional>
#include <map>
#include <string>
#include <string_view>

namespace bot_shield {

using QueryParams = std::map<std::string, std::string, std::less<>>;

// Decodes %XX escapes and '+' (as a space).
std::string PercentDecode(std::string_view text);
// Encodes everything but unreserved characters (RFC 3986).
std::string PercentEncode(std::string_view text);

// "a=1&b=x%20y" -> {a: "1", b: "x y"}.
QueryParams ParseQuery(std::string_view query);

// Value of `name`, or "".
std::string QueryParam(const QueryParams& params, std::string_view name);

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_URL_H_
