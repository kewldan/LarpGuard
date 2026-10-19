#ifndef BOT_SHIELD_CHALLENGE_SCRIPTS_H_
#define BOT_SHIELD_CHALLENGE_SCRIPTS_H_

#include <string_view>

namespace bot_shield {

// Scripts of the gateway's own pages. Plain ES5 plus Promise, no external
// resources; inlined into the pages.

// sha256(bytes), zeroBits(hash), solve(nonce, bits), hex(bytes), h(text)
// (16 hex chars of SHA-256), b64url(text).
std::string_view CryptoJs();

// collect(callback): browser signals and probes (navigator, canvas, WebGL,
// audio, fonts, screen, Worker, native tampering, CDP) as one object.
std::string_view ProbesJs();

// The JS challenge: expects N (nonce) and D (difficulty) in scope.
std::string_view ChallengeJs();

// Third-party CAPTCHA widgets call bsCaptchaDone(token): collects probes,
// solves a small proof of work and submits. Expects N, D.
std::string_view WidgetJs();

// The built-in puzzle: records pointer movement, posts clicks to
// /__bs/captcha/answer and shows the next round. Expects N, D.
std::string_view PuzzleJs();

}  // namespace bot_shield

#endif  // BOT_SHIELD_CHALLENGE_SCRIPTS_H_
