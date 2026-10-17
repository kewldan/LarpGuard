#ifndef BOT_SHIELD_FP_HTTP_FINGERPRINT_H_
#define BOT_SHIELD_FP_HTTP_FINGERPRINT_H_

#include <string>

#include "fp/http_request.h"

namespace bot_shield {

// bot-shield header-order fingerprint:
//   <version>:<header count>:<sha256 of names joined by ',', 12 hex chars>
// Names keep their wire case and order, so clients that send the same headers
// in a different order or case get different fingerprints. Example:
//   1.1:7:3f4e2a1b9c0d
std::string HeaderOrderFingerprint(const HttpRequest& request);

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_HTTP_FINGERPRINT_H_
