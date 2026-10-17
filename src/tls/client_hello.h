#ifndef BOT_SHIELD_TLS_CLIENT_HELLO_H_
#define BOT_SHIELD_TLS_CLIENT_HELLO_H_

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {

// Fields of a TLS ClientHello needed for routing now and for fingerprinting
// (JA4) later. Lists keep wire order and GREASE values.
struct ClientHello {
  bool HasAlpn(std::string_view protocol) const;

  uint16_t legacy_version = 0;
  // Normalized (lowercase, no trailing dot); empty if the SNI is absent.
  std::string server_name;
  std::vector<std::string> alpn;
  std::vector<uint16_t> cipher_suites;
  std::vector<uint16_t> extensions;
  std::vector<uint16_t> supported_groups;
  std::vector<uint16_t> signature_algorithms;
  std::vector<uint16_t> supported_versions;
  std::vector<uint8_t> ec_point_formats;
};

enum class ParseStatus {
  kOk,
  // The bytes so far are a valid prefix of a ClientHello; read more.
  kNeedMore,
  // The stream does not start with a TLS handshake record.
  kNotTls,
  // A TLS record, but not a well-formed ClientHello.
  kInvalid,
};

// Upper bound on the bytes buffered while waiting for a complete ClientHello.
// Post-quantum key shares make ~2 KB hellos common; 32 KB leaves headroom.
inline constexpr std::size_t kMaxClientHelloBytes = 32 * 1024;

// Parses a ClientHello from the first bytes of a connection. The handshake
// message may be split across several TLS records and several reads.
ParseStatus ParseClientHello(std::span<const uint8_t> data, ClientHello* hello);

}  // namespace bot_shield

#endif  // BOT_SHIELD_TLS_CLIENT_HELLO_H_
