#include "fp/http_request.h"

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

}  // namespace bot_shield
