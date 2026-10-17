// JA4+ methods under the FoxIO License 1.1, see LICENSE.md next to this file.
#include "fp/foxio/ja4plus.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "common/hash.h"
#include "fp/http_request.h"
#include "fp/tcp_syn.h"

namespace bot_shield::foxio {
namespace {

constexpr std::size_t kHashChars = 12;
constexpr std::string_view kEmptyHash = "000000000000";

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

std::string_view Trim(std::string_view text) {
  while (!text.empty() && text.front() == ' ') text.remove_prefix(1);
  while (!text.empty() && text.back() == ' ') text.remove_suffix(1);
  return text;
}

std::string Join(const std::vector<std::string>& items) {
  std::string out;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i > 0) out.push_back(',');
    out += items[i];
  }
  return out;
}

std::string HashOrEmpty(const std::string& text) {
  return text.empty() ? std::string(kEmptyHash) : Sha256Hex(text, kHashChars);
}

std::string VersionCode(std::string_view version) {
  if (version == "2") return "20";
  if (version == "3") return "30";
  std::string code;
  for (const char c : version) {
    if (c != '.') code.push_back(c);
  }
  return code.size() == 2 ? code : "00";
}

// First language tag of Accept-Language: lowercase, without '-', first four
// characters, padded with '0'.
std::string LanguageCode(std::string_view accept_language) {
  std::string code;
  for (const char c : accept_language) {
    if (c == ',' || c == ';') break;
    if (c == '-' || c == ' ') continue;
    code.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (code.size() == 4) break;
  }
  code.resize(4, '0');
  return code;
}

}  // namespace

std::string Ja4t(const TcpSyn& syn) {
  std::string options;
  for (const uint8_t kind : syn.options) {
    if (!options.empty()) options.push_back('-');
    options += std::to_string(kind);
  }
  return std::format("{}_{}_{}_{}", syn.window,
                     options.empty() ? "00" : options,
                     syn.mss == 0 ? std::string("00") : std::to_string(syn.mss),
                     syn.window_scale < 0 ? std::string("00")
                                          : std::to_string(syn.window_scale));
}

std::string Ja4h(const HttpRequest& request) {
  std::vector<std::string> names;
  std::vector<std::string> cookie_names;
  std::vector<std::string> cookie_fields;
  bool has_cookie = false;
  bool has_referer = false;
  for (const std::string& name : request.header_names) {
    const std::string lowercase = Lowercase(name);
    if (lowercase == "cookie") {
      has_cookie = true;
    } else if (lowercase == "referer") {
      has_referer = true;
    } else {
      names.push_back(name);
    }
  }
  for (const auto& [name, value] : request.headers) {
    if (name != "cookie") continue;
    std::string_view rest = value;
    while (!rest.empty()) {
      const std::size_t end = rest.find(';');
      const std::string_view field = Trim(rest.substr(0, end));
      rest = end == std::string_view::npos ? std::string_view()
                                           : rest.substr(end + 1);
      if (field.empty()) continue;
      cookie_fields.emplace_back(field);
      cookie_names.emplace_back(field.substr(0, field.find('=')));
    }
  }
  std::ranges::sort(cookie_names);
  std::ranges::sort(cookie_fields);

  std::string method = Lowercase(request.method).substr(0, 2);
  method.resize(2, '0');
  const std::string prefix =
      std::format("{}{}{}{}{:02}{}", method, VersionCode(request.version),
                  has_cookie ? 'c' : 'n', has_referer ? 'r' : 'n',
                  std::min<std::size_t>(names.size(), 99),
                  LanguageCode(request.Header("accept-language")));
  return std::format("{}_{}_{}_{}", prefix, HashOrEmpty(Join(names)),
                     HashOrEmpty(Join(cookie_names)),
                     HashOrEmpty(Join(cookie_fields)));
}

}  // namespace bot_shield::foxio
