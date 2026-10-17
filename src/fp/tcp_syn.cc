#include "fp/tcp_syn.h"

#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <span>
#include <string>

namespace bot_shield {
namespace {

constexpr uint8_t kProtocolTcp = 6;
constexpr std::size_t kIpv6HeaderSize = 40;
constexpr std::size_t kTcpMinHeaderSize = 20;

constexpr uint8_t kOptionEol = 0;
constexpr uint8_t kOptionNop = 1;
constexpr uint8_t kOptionMss = 2;
constexpr uint8_t kOptionWindowScale = 3;
constexpr uint8_t kOptionSackPermitted = 4;
constexpr uint8_t kOptionTimestamps = 8;

uint16_t ReadU16(std::span<const uint8_t> data, std::size_t offset) {
  return static_cast<uint16_t>((unsigned{data[offset]} << 8) |
                               data[offset + 1]);
}

bool ParseOptions(std::span<const uint8_t> options, TcpSyn* syn) {
  std::size_t i = 0;
  while (i < options.size()) {
    const uint8_t kind = options[i];
    syn->options.push_back(kind);
    if (kind == kOptionEol) break;
    if (kind == kOptionNop) {
      ++i;
      continue;
    }
    if (i + 1 >= options.size()) return false;
    const uint8_t size = options[i + 1];
    if (size < 2 || i + size > options.size()) return false;
    const auto value = options.subspan(i + 2, size - 2);
    if (kind == kOptionMss && value.size() == 2) {
      syn->mss = ReadU16(value, 0);
    } else if (kind == kOptionWindowScale && value.size() == 1) {
      syn->window_scale = value[0];
    }
    i += size;
  }
  return true;
}

bool ParseTcp(std::span<const uint8_t> tcp, TcpSyn* syn) {
  if (tcp.size() < kTcpMinHeaderSize) return false;
  const std::size_t header_size = (tcp[12] >> 4) * std::size_t{4};
  if (header_size < kTcpMinHeaderSize || header_size > tcp.size()) {
    return false;
  }
  constexpr uint8_t kFlagEce = 0x40;
  constexpr uint8_t kFlagCwr = 0x80;
  syn->window = ReadU16(tcp, 14);
  syn->ecn = (tcp[13] & kFlagEce) != 0 && (tcp[13] & kFlagCwr) != 0;
  return ParseOptions(
      tcp.subspan(kTcpMinHeaderSize, header_size - kTcpMinHeaderSize), syn);
}

char OptionLetter(uint8_t kind) {
  switch (kind) {
    case kOptionEol:
      return 'E';
    case kOptionNop:
      return 'N';
    case kOptionMss:
      return 'M';
    case kOptionWindowScale:
      return 'W';
    case kOptionSackPermitted:
      return 'S';
    case kOptionTimestamps:
      return 'T';
    default:
      return '?';
  }
}

}  // namespace

bool ParseTcpSyn(std::span<const uint8_t> packet, TcpSyn* syn) {
  *syn = TcpSyn{};
  if (packet.empty()) return false;
  syn->ip_version = packet[0] >> 4;
  if (syn->ip_version == 4) {
    if (packet.size() < 20) return false;
    const std::size_t header_size = (packet[0] & 0x0F) * std::size_t{4};
    if (header_size < 20 || header_size > packet.size() ||
        packet[9] != kProtocolTcp) {
      return false;
    }
    constexpr uint8_t kFlagDontFragment = 0x40;
    syn->ttl = packet[8];
    syn->dont_fragment = (packet[6] & kFlagDontFragment) != 0;
    return ParseTcp(packet.subspan(header_size), syn);
  }
  if (syn->ip_version == 6) {
    if (packet.size() < kIpv6HeaderSize || packet[6] != kProtocolTcp) {
      return false;
    }
    syn->ttl = packet[7];
    return ParseTcp(packet.subspan(kIpv6HeaderSize), syn);
  }
  return false;
}

uint8_t InitialTtl(uint8_t ttl) {
  if (ttl <= 32) return 32;
  if (ttl <= 64) return 64;
  if (ttl <= 128) return 128;
  return 255;
}

std::string TcpFingerprint(const TcpSyn& syn) {
  std::string options;
  for (const uint8_t kind : syn.options) {
    const char letter = OptionLetter(kind);
    options.push_back(letter);
    if (letter == '?') options += std::to_string(kind);
  }
  std::string flags;
  if (syn.dont_fragment) flags = "df";
  if (syn.ecn) flags += flags.empty() ? "ecn" : "+ecn";
  if (flags.empty()) flags = "-";

  std::string out;
  std::format_to(std::back_inserter(out), "{}:{}:{}:{}:{}:{}:{}",
                 syn.ip_version, InitialTtl(syn.ttl), syn.window, syn.mss,
                 syn.window_scale, options.empty() ? "-" : options, flags);
  return out;
}

}  // namespace bot_shield
