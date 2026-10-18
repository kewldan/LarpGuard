#include "common/url.h"

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace bot_shield {
namespace {

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::string PercentDecode(std::string_view text) {
  std::string out;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '+') {
      out.push_back(' ');
    } else if (text[i] == '%' && i + 2 < text.size() &&
               HexValue(text[i + 1]) >= 0 && HexValue(text[i + 2]) >= 0) {
      out.push_back(static_cast<char>(HexValue(text[i + 1]) * 16 +
                                      HexValue(text[i + 2])));
      i += 2;
    } else {
      out.push_back(text[i]);
    }
  }
  return out;
}

std::string PercentEncode(std::string_view text) {
  static constexpr char kDigits[] = "0123456789ABCDEF";
  std::string out;
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if (std::isalnum(byte) != 0 || c == '-' || c == '_' || c == '.' ||
        c == '~') {
      out.push_back(c);
    } else {
      out.push_back('%');
      out.push_back(kDigits[byte >> 4]);
      out.push_back(kDigits[byte & 0x0F]);
    }
  }
  return out;
}

QueryParams ParseQuery(std::string_view query) {
  QueryParams params;
  while (!query.empty()) {
    const std::size_t amp = query.find('&');
    const std::string_view pair = query.substr(0, amp);
    const std::size_t equals = pair.find('=');
    params[PercentDecode(pair.substr(0, equals))] =
        equals == std::string_view::npos
            ? ""
            : PercentDecode(pair.substr(equals + 1));
    if (amp == std::string_view::npos) break;
    query.remove_prefix(amp + 1);
  }
  return params;
}

std::string QueryParam(const QueryParams& params, std::string_view name) {
  const auto it = params.find(name);
  return it == params.end() ? std::string() : it->second;
}

}  // namespace bot_shield
