#include "common/host.h"

#include <string>
#include <string_view>

namespace bot_shield {

std::string NormalizeHost(std::string_view host) {
  if (!host.empty() && host.back() == '.') host.remove_suffix(1);
  std::string result(host);
  for (char& c : result) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return result;
}

std::string_view ParentDomain(std::string_view host) {
  const auto dot = host.find('.');
  if (dot == std::string_view::npos) return {};
  return host.substr(dot + 1);
}

bool IsValidHostName(std::string_view host) {
  if (host.empty() || host.size() > 253) return false;
  char previous = '.';
  for (char c : host) {
    const bool allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                         c == '-' || c == '_' || c == '.';
    if (!allowed) return false;
    if (c == '.' && previous == '.') return false;
    previous = c;
  }
  return previous != '.';
}

bool HostMatches(std::string_view pattern, std::string_view host) {
  if (pattern.starts_with("*.")) {
    const std::string_view parent = ParentDomain(host);
    return !parent.empty() && parent == pattern.substr(2);
  }
  return pattern == host;
}

}  // namespace bot_shield
