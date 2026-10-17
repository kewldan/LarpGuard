#include "fp/http_fingerprint.h"

#include <cstddef>
#include <format>
#include <string>

#include "common/hash.h"
#include "fp/http_request.h"

namespace bot_shield {

std::string HeaderOrderFingerprint(const HttpRequest& request) {
  std::string names;
  for (std::size_t i = 0; i < request.header_names.size(); ++i) {
    if (i > 0) names.push_back(',');
    names += request.header_names[i];
  }
  return std::format("{}:{}:{}", request.version, request.header_names.size(),
                     Sha256Hex(names, 12));
}

}  // namespace bot_shield
