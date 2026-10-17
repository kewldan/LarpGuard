#ifndef BOT_SHIELD_COMMON_HOST_H_
#define BOT_SHIELD_COMMON_HOST_H_

#include <string>
#include <string_view>

namespace bot_shield {

// Lowercases ASCII letters and strips a single trailing dot.
std::string NormalizeHost(std::string_view host);

// Returns everything after the first label: "a.example.com" -> "example.com".
// Returns an empty view if `host` has no dot.
std::string_view ParentDomain(std::string_view host);

// True for a non-empty DNS name of at most 253 characters made of
// [a-z0-9-_.] with no empty labels. Expects a normalized host.
bool IsValidHostName(std::string_view host);

// True if `host` matches `pattern`, where the pattern is either an exact name
// or "*.parent" matching exactly one extra label. Both must be normalized.
bool HostMatches(std::string_view pattern, std::string_view host);

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_HOST_H_
