#ifndef BOT_SHIELD_FP_FOXIO_JA4PLUS_H_
#define BOT_SHIELD_FP_FOXIO_JA4PLUS_H_

// JA4+ methods under the FoxIO License 1.1, see LICENSE.md next to this file.
// Compiled only with -DBOT_SHIELD_FOXIO=ON (BOT_SHIELD_FOXIO is then 1).

#include <string>

#include "fp/http_request.h"
#include "fp/tcp_syn.h"

namespace bot_shield::foxio {

// JA4T: <window>_<option kinds joined by '-'>_<mss>_<window scale>, with
// "00" for absent parts. Example: 64240_2-1-3-1-1-4_1460_8
std::string Ja4t(const TcpSyn& syn);

// JA4H: <method><version><cookie><referer><header count><language>
//       _<header names hash>_<cookie names hash>_<cookie fields hash>
// Example: ge11cn060000_4e59edc1297a_000000000000_000000000000
std::string Ja4h(const HttpRequest& request);

}  // namespace bot_shield::foxio

#endif  // BOT_SHIELD_FP_FOXIO_JA4PLUS_H_
