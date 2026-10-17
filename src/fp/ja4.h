#ifndef BOT_SHIELD_FP_JA4_H_
#define BOT_SHIELD_FP_JA4_H_

#include <cstdint>
#include <string>
#include <string_view>

#include "tls/client_hello.h"

namespace bot_shield {

// True for GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ..., 0xfafa.
bool IsGrease(uint16_t value);

// JA4 TLS client fingerprint (FoxIO, BSD 3-Clause), e.g.
// t13d1516h2_8daaf6152771_e5627efa2ab1. `transport` is 't' for TCP and 'q'
// for QUIC.
std::string Ja4(const ClientHello& hello, char transport = 't');

// JA4_r: the same with the sorted cipher and extension lists in clear text
// instead of hashes, for analysis.
std::string Ja4Raw(const ClientHello& hello, char transport = 't');

// "13", "12", ... for the highest offered TLS version (ignores GREASE).
std::string_view TlsVersionCode(const ClientHello& hello);

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_JA4_H_
