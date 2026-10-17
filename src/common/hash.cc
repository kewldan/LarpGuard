#include "common/hash.h"

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bot_shield {

std::string HexEncode(std::string_view bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const char c : bytes) {
    const auto byte = static_cast<uint8_t>(c);
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0F]);
  }
  return out;
}

std::string Sha256Hex(std::string_view data, std::size_t hex_chars) {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
         digest.data());
  std::string hex = HexEncode(std::string_view(
      reinterpret_cast<const char*>(digest.data()), digest.size()));
  hex.resize(std::min(hex_chars, hex.size()));
  return hex;
}

std::string HmacSha256Hex(std::string_view key, std::string_view data,
                          std::size_t hex_chars) {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  unsigned size = 0;
  HMAC(EVP_sha256(), key.data(), key.size(),
       reinterpret_cast<const uint8_t*>(data.data()), data.size(),
       digest.data(), &size);
  std::string hex = HexEncode(
      std::string_view(reinterpret_cast<const char*>(digest.data()), size));
  hex.resize(std::min(hex_chars, hex.size()));
  return hex;
}

}  // namespace bot_shield
