#ifndef BOT_SHIELD_FP_TCP_SYN_H_
#define BOT_SHIELD_FP_TCP_SYN_H_

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace bot_shield {

// Fields of a client's TCP SYN (IP + TCP headers as saved by the kernel with
// TCP_SAVED_SYN) that reflect the client's network stack.
struct TcpSyn {
  uint8_t ip_version = 0;
  // TTL / hop limit as received (already decremented by each hop).
  uint8_t ttl = 0;
  bool dont_fragment = false;
  uint16_t window = 0;
  // ECE and CWR set in the SYN: the client asks for ECN.
  bool ecn = false;
  // Option kinds in wire order, including NOP (1) and EOL (0).
  std::vector<uint8_t> options;
  // 0 when the option is absent.
  uint16_t mss = 0;
  // -1 when the option is absent.
  int window_scale = -1;
};

// Parses an IPv4 or IPv6 packet carrying a TCP SYN. IPv6 extension headers
// are not followed (returns false).
bool ParseTcpSyn(std::span<const uint8_t> packet, TcpSyn* syn);

// Rounds an observed TTL up to the likely initial value (32, 64, 128, 255).
uint8_t InitialTtl(uint8_t ttl);

// bot-shield TCP fingerprint:
//   <ip version>:<initial ttl>:<window>:<mss>:<window scale>:<options>:<flags>
// options are letters in wire order (M mss, N nop, W window scale, S sack
// permitted, T timestamps, E eol, ?<kind> other), flags are "df", "ecn" joined
// by '+' or "-". Example: 4:64:64240:1460:7:MSTNW:df
std::string TcpFingerprint(const TcpSyn& syn);

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_TCP_SYN_H_
