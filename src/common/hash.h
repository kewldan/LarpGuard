#ifndef BOT_SHIELD_COMMON_HASH_H_
#define BOT_SHIELD_COMMON_HASH_H_

#include <cstddef>
#include <string>
#include <string_view>

namespace bot_shield {

// Lowercase hex of SHA-256(`data`), truncated to `hex_chars` characters.
std::string Sha256Hex(std::string_view data, std::size_t hex_chars = 64);

// Lowercase hex of HMAC-SHA256(`key`, `data`), truncated to `hex_chars`.
std::string HmacSha256Hex(std::string_view key, std::string_view data,
                          std::size_t hex_chars = 64);

// Lowercase hex encoding of raw bytes.
std::string HexEncode(std::string_view bytes);

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_HASH_H_
