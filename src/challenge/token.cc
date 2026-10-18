#include "challenge/token.h"

#include <openssl/base64.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/hash.h"

namespace bot_shield {
namespace {

constexpr std::size_t kMacChars = 32;  // 128 bits.
constexpr std::size_t kMinSecret = 32;

std::vector<std::string_view> Split(std::string_view text, char separator) {
  std::vector<std::string_view> parts;
  while (true) {
    const std::size_t at = text.find(separator);
    parts.push_back(text.substr(0, at));
    if (at == std::string_view::npos) return parts;
    text.remove_prefix(at + 1);
  }
}

bool ParseInt(std::string_view text, int64_t* value) {
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), *value);
  return ec == std::errc() && ptr == text.data() + text.size();
}

bool IsHex(std::string_view text, std::size_t size) {
  return text.size() == size &&
         text.find_first_not_of("0123456789abcdef-") == std::string_view::npos;
}

std::string Mac(std::string_view secret, std::string_view payload) {
  return HmacSha256Hex(secret, payload, kMacChars);
}

bool MacMatches(const std::string& expected, std::string_view actual) {
  return expected.size() == actual.size() &&
         CRYPTO_memcmp(expected.data(), actual.data(), expected.size()) == 0;
}

// Splits "<payload>.<key id>.<mac>" and checks the MAC.
bool CheckSigned(const TokenKeys& keys, std::string_view text,
                 std::vector<std::string_view>* fields) {
  const std::size_t mac_at = text.rfind('.');
  if (mac_at == std::string_view::npos) return false;
  const std::size_t key_at = text.rfind('.', mac_at - 1);
  if (key_at == std::string_view::npos || key_at == 0) return false;
  const std::string_view signed_part = text.substr(0, mac_at);
  const std::string_view key_id = text.substr(key_at + 1, mac_at - key_at - 1);
  const std::string_view secret = keys.Secret(key_id);
  if (secret.empty() ||
      !MacMatches(Mac(secret, signed_part), text.substr(mac_at + 1))) {
    return false;
  }
  *fields = Split(text.substr(0, key_at), '.');
  return true;
}

}  // namespace

bool TokenKeys::Load(const std::string& path, TokenKeys* keys,
                     std::string* error) {
  std::ifstream file(path);
  if (!file) {
    *error = std::format("cannot open {}", path);
    return false;
  }
  std::stringstream contents;
  contents << file.rdbuf();
  const nlohmann::json root =
      nlohmann::json::parse(contents.str(), nullptr, false);
  if (root.is_discarded() || !root.is_object() || !root.contains("active") ||
      !root["active"].is_string() || !root.contains("keys") ||
      !root["keys"].is_object()) {
    *error =
        std::format(R"({}: expected {{"active": ..., "keys": {{...}}}})", path);
    return false;
  }
  TokenKeys out;
  out.active_ = root["active"].get<std::string>();
  for (const auto& [id, value] : root["keys"].items()) {
    std::string secret;
    if (!value.is_string() || id.empty() || id.find('.') != std::string::npos) {
      *error = std::format("{}: bad key '{}'", path, id);
      return false;
    }
    const std::string encoded = value.get<std::string>();
    std::size_t size = 0;
    EVP_DecodedLength(&size, encoded.size());
    secret.resize(size);
    if (!EVP_DecodeBase64(
            reinterpret_cast<uint8_t*>(secret.data()), &size, size,
            reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size())) {
      *error = std::format("{}: key '{}' is not base64", path, id);
      return false;
    }
    secret.resize(size);
    if (secret.size() < kMinSecret) {
      *error = std::format("{}: key '{}' is shorter than {} bytes", path, id,
                           kMinSecret);
      return false;
    }
    out.secrets_[id] = std::move(secret);
  }
  if (out.Secret(out.active_).empty()) {
    *error =
        std::format("{}: active key '{}' is not in keys", path, out.active_);
    return false;
  }
  *keys = std::move(out);
  return true;
}

TokenKeys TokenKeys::Random() {
  TokenKeys keys;
  std::string secret(kMinSecret, '\0');
  RAND_bytes(reinterpret_cast<uint8_t*>(secret.data()), secret.size());
  keys.active_ = "r" + HexEncode(secret).substr(0, 6);
  keys.secrets_[keys.active_] = std::move(secret);
  return keys;
}

std::string_view TokenKeys::Secret(std::string_view id) const {
  const auto it = secrets_.find(id);
  return it == secrets_.end() ? std::string_view()
                              : std::string_view(it->second);
}

ClientBinding ClientBinding::For(std::string_view ja4,
                                 std::string_view ip_prefix) {
  return {ja4.empty() ? std::string(8, '-') : Sha256Hex(ja4, 8),
          Sha256Hex(ip_prefix, 8)};
}

std::string IssueToken(const TokenKeys& keys, const TokenClaims& claims) {
  const std::string payload = std::format(
      "v1.{}.{}.{}.{}.{}", claims.issued, claims.expires,
      claims.binding.ja4_hash, claims.binding.ip_hash, keys.active_id());
  return payload + "." + Mac(keys.Secret(keys.active_id()), payload);
}

bool VerifyToken(const TokenKeys& keys, std::string_view token, int64_t now,
                 TokenClaims* claims) {
  std::vector<std::string_view> fields;
  if (!CheckSigned(keys, token, &fields) || fields.size() != 5 ||
      fields[0] != "v1") {
    return false;
  }
  TokenClaims out;
  if (!ParseInt(fields[1], &out.issued) || !ParseInt(fields[2], &out.expires) ||
      !IsHex(fields[3], 8) || !IsHex(fields[4], 8) || out.expires <= now) {
    return false;
  }
  out.binding = {std::string(fields[3]), std::string(fields[4])};
  *claims = std::move(out);
  return true;
}

std::string IssueNonce(const TokenKeys& keys, const NonceClaims& claims) {
  const std::string payload =
      std::format("n1.{}.{}.{}.{}.{}.{}", claims.issued, claims.difficulty,
                  claims.binding.ja4_hash, claims.binding.ip_hash,
                  Base64UrlEncode(claims.return_path), keys.active_id());
  return payload + "." + Mac(keys.Secret(keys.active_id()), payload);
}

bool VerifyNonce(const TokenKeys& keys, std::string_view nonce, int64_t now,
                 int64_t max_age_seconds, NonceClaims* claims) {
  std::vector<std::string_view> fields;
  if (!CheckSigned(keys, nonce, &fields) || fields.size() != 6 ||
      fields[0] != "n1") {
    return false;
  }
  NonceClaims out;
  int64_t difficulty = 0;
  if (!ParseInt(fields[1], &out.issued) || !ParseInt(fields[2], &difficulty) ||
      difficulty < 0 || difficulty > 32 || !IsHex(fields[3], 8) ||
      !IsHex(fields[4], 8) || !Base64UrlDecode(fields[5], &out.return_path) ||
      now - out.issued > max_age_seconds || out.issued > now + 60) {
    return false;
  }
  out.difficulty = static_cast<int>(difficulty);
  out.binding = {std::string(fields[3]), std::string(fields[4])};
  *claims = std::move(out);
  return true;
}

int PowZeroBits(std::string_view nonce, std::string_view counter) {
  const std::string input = std::format("{}:{}", nonce, counter);
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  SHA256(reinterpret_cast<const uint8_t*>(input.data()), input.size(),
         digest.data());
  int bits = 0;
  for (const uint8_t byte : digest) {
    if (byte == 0) {
      bits += 8;
      continue;
    }
    for (int bit = 7; bit >= 0 && (byte & (1 << bit)) == 0; --bit) ++bits;
    break;
  }
  return bits;
}

bool IsSafeReturnPath(std::string_view path) {
  return path.starts_with('/') && !path.starts_with("//") &&
         !path.starts_with("/\\") &&
         path.find_first_of("\r\n") == std::string_view::npos;
}

std::string Base64UrlEncode(std::string_view data) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  std::size_t i = 0;
  for (; i + 2 < data.size(); i += 3) {
    const uint32_t chunk = (uint32_t{static_cast<uint8_t>(data[i])} << 16) |
                           (uint32_t{static_cast<uint8_t>(data[i + 1])} << 8) |
                           static_cast<uint8_t>(data[i + 2]);
    out += kAlphabet[(chunk >> 18) & 63];
    out += kAlphabet[(chunk >> 12) & 63];
    out += kAlphabet[(chunk >> 6) & 63];
    out += kAlphabet[chunk & 63];
  }
  if (i + 1 == data.size()) {
    const uint32_t chunk = uint32_t{static_cast<uint8_t>(data[i])} << 16;
    out += kAlphabet[(chunk >> 18) & 63];
    out += kAlphabet[(chunk >> 12) & 63];
  } else if (i + 2 == data.size()) {
    const uint32_t chunk = (uint32_t{static_cast<uint8_t>(data[i])} << 16) |
                           (uint32_t{static_cast<uint8_t>(data[i + 1])} << 8);
    out += kAlphabet[(chunk >> 18) & 63];
    out += kAlphabet[(chunk >> 12) & 63];
    out += kAlphabet[(chunk >> 6) & 63];
  }
  return out;
}

bool Base64UrlDecode(std::string_view text, std::string* data) {
  const auto value = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
  };
  if (text.size() % 4 == 1) return false;
  std::string out;
  uint32_t buffer = 0;
  int bits = 0;
  for (const char c : text) {
    const int v = value(c);
    if (v < 0) return false;
    buffer = (buffer << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
    }
  }
  *data = std::move(out);
  return true;
}

}  // namespace bot_shield
