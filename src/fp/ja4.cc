#include "fp/ja4.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "common/hash.h"
#include "tls/client_hello.h"

namespace bot_shield {
namespace {

constexpr uint16_t kExtServerName = 0x0000;
constexpr uint16_t kExtAlpn = 0x0010;
constexpr std::size_t kHashChars = 12;
constexpr std::string_view kEmptyHash = "000000000000";

std::vector<uint16_t> WithoutGrease(const std::vector<uint16_t>& values) {
  std::vector<uint16_t> out;
  out.reserve(values.size());
  for (const uint16_t value : values) {
    if (!IsGrease(value)) out.push_back(value);
  }
  return out;
}

std::string JoinHex(const std::vector<uint16_t>& values) {
  std::string out;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i > 0) out.push_back(',');
    out += std::format("{:04x}", values[i]);
  }
  return out;
}

bool IsAlphanumeric(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0;
}

std::string AlpnCode(const ClientHello& hello) {
  if (hello.alpn.empty() || hello.alpn.front().empty()) return "00";
  const std::string& alpn = hello.alpn.front();
  if (IsAlphanumeric(alpn.front()) && IsAlphanumeric(alpn.back())) {
    return {alpn.front(), alpn.back()};
  }
  const std::string hex = HexEncode(alpn);
  return {hex.front(), hex.back()};
}

std::string Count(std::size_t n) {
  return std::format("{:02}", std::min<std::size_t>(n, 99));
}

struct Parts {
  std::string prefix;
  std::string ciphers;     // sorted, comma-joined hex
  std::string extensions;  // sorted (no SNI/ALPN) [+ "_" + sig algs]
};

Parts BuildParts(const ClientHello& hello, char transport) {
  std::vector<uint16_t> ciphers = WithoutGrease(hello.cipher_suites);
  const std::vector<uint16_t> extensions = WithoutGrease(hello.extensions);
  const std::vector<uint16_t> signature_algorithms =
      WithoutGrease(hello.signature_algorithms);

  Parts parts;
  parts.prefix =
      std::format("{}{}{}{}{}{}", transport, TlsVersionCode(hello),
                  hello.server_name.empty() ? 'i' : 'd', Count(ciphers.size()),
                  Count(extensions.size()), AlpnCode(hello));

  std::ranges::sort(ciphers);
  parts.ciphers = JoinHex(ciphers);

  std::vector<uint16_t> hashed_extensions;
  for (const uint16_t type : extensions) {
    if (type != kExtServerName && type != kExtAlpn) {
      hashed_extensions.push_back(type);
    }
  }
  std::ranges::sort(hashed_extensions);
  parts.extensions = JoinHex(hashed_extensions);
  if (!signature_algorithms.empty()) {
    parts.extensions += "_" + JoinHex(signature_algorithms);
  }
  return parts;
}

std::string HashOrEmpty(const std::string& text) {
  return text.empty() ? std::string(kEmptyHash) : Sha256Hex(text, kHashChars);
}

}  // namespace

bool IsGrease(uint16_t value) {
  return (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);
}

std::string_view TlsVersionCode(const ClientHello& hello) {
  uint16_t version = 0;
  for (const uint16_t offered : hello.supported_versions) {
    if (!IsGrease(offered)) version = std::max(version, offered);
  }
  if (version == 0) version = hello.legacy_version;
  switch (version) {
    case 0x0304:
      return "13";
    case 0x0303:
      return "12";
    case 0x0302:
      return "11";
    case 0x0301:
      return "10";
    case 0x0300:
      return "s3";
    case 0x0002:
      return "s2";
    case 0xFEFF:
      return "d1";
    case 0xFEFD:
      return "d2";
    case 0xFEFC:
      return "d3";
    default:
      return "00";
  }
}

std::string Ja4(const ClientHello& hello, char transport) {
  const Parts parts = BuildParts(hello, transport);
  return std::format("{}_{}_{}", parts.prefix, HashOrEmpty(parts.ciphers),
                     HashOrEmpty(parts.extensions));
}

std::string Ja4Raw(const ClientHello& hello, char transport) {
  const Parts parts = BuildParts(hello, transport);
  return std::format("{}_{}_{}", parts.prefix, parts.ciphers, parts.extensions);
}

}  // namespace bot_shield
