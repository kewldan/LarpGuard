#include "fp/http_request.h"

#include <cstddef>
#include <optional>
#include <string_view>

namespace bot_shield {

std::string_view HttpRequest::Header(std::string_view lowercase_name) const {
  for (const auto& [name, value] : headers) {
    if (name == lowercase_name) return value;
  }
  return {};
}

bool HttpRequest::HasHeader(std::string_view lowercase_name) const {
  for (const auto& [name, value] : headers) {
    if (name == lowercase_name) return true;
  }
  return false;
}

std::optional<std::string_view> FindCookie(const HttpRequest& request,
                                           std::string_view name) {
  for (const auto& [header, value] : request.headers) {
    if (header != "cookie") continue;
    std::string_view rest = value;
    while (!rest.empty()) {
      const std::size_t end = rest.find(';');
      std::string_view field = rest.substr(0, end);
      while (!field.empty() && field.front() == ' ') field.remove_prefix(1);
      const std::size_t equals = field.find('=');
      if (equals != std::string_view::npos && field.substr(0, equals) == name) {
        return field.substr(equals + 1);
      }
      if (end == std::string_view::npos) break;
      rest.remove_prefix(end + 1);
    }
  }
  return std::nullopt;
}

std::optional<std::string_view> FindQueryParam(std::string_view query,
                                               std::string_view name) {
  while (!query.empty()) {
    const std::size_t end = query.find('&');
    const std::string_view pair = query.substr(0, end);
    const std::size_t equals = pair.find('=');
    if (pair.substr(0, equals) == name) {
      return equals == std::string_view::npos ? std::string_view()
                                              : pair.substr(equals + 1);
    }
    if (end == std::string_view::npos) break;
    query.remove_prefix(end + 1);
  }
  return std::nullopt;
}

}  // namespace bot_shield
