#ifndef BOT_SHIELD_CHALLENGE_TOKEN_H_
#define BOT_SHIELD_CHALLENGE_TOKEN_H_

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace bot_shield {

// HMAC keys for challenge nonces and clearance tokens. Several keys can be
// accepted while one signs, so keys rotate without logging everyone out.
class TokenKeys {
 public:
  // JSON file: {"active": "k2", "keys": {"k1": "<base64>", "k2": "<base64>"}}
  // with secrets of at least 32 bytes.
  static bool Load(const std::string& path, TokenKeys* keys,
                   std::string* error);
  // One random key; tokens do not survive a restart.
  static TokenKeys Random();

  const std::string& active_id() const { return active_; }
  // Secret by id; empty if unknown.
  std::string_view Secret(std::string_view id) const;

 private:
  std::string active_;
  std::map<std::string, std::string, std::less<>> secrets_;
};

// What a token or nonce is bound to: the client's TLS stack and network.
struct ClientBinding {
  std::string ja4_hash;  // 8 hex chars of SHA-256(ja4); "-" without TLS.
  std::string ip_hash;   // 8 hex chars of SHA-256(ip prefix).

  static ClientBinding For(std::string_view ja4, std::string_view ip_prefix);
  friend bool operator==(const ClientBinding&, const ClientBinding&) = default;
};

// Clearance token (cookie __bs):
//   v1.<issued>.<expires>.<ja4 hash>.<ip hash>.<key id>.<mac>
struct TokenClaims {
  int64_t issued = 0;   // Unix seconds.
  int64_t expires = 0;  // Unix seconds.
  ClientBinding binding;
};

std::string IssueToken(const TokenKeys& keys, const TokenClaims& claims);
// Checks format, MAC and expiry (binding is compared by the caller).
bool VerifyToken(const TokenKeys& keys, std::string_view token, int64_t now,
                 TokenClaims* claims);

// Challenge nonce, given to the page and returned with the solution:
//   n1.<issued>.<difficulty>.<ja4 hash>.<ip hash>.<return path b64>.<key>.<mac>
struct NonceClaims {
  int64_t issued = 0;
  int difficulty = 0;
  ClientBinding binding;
  std::string return_path;
};

std::string IssueNonce(const TokenKeys& keys, const NonceClaims& claims);
// Checks format, MAC and age (`max_age_seconds`).
bool VerifyNonce(const TokenKeys& keys, std::string_view nonce, int64_t now,
                 int64_t max_age_seconds, NonceClaims* claims);

// Number of leading zero bits of SHA-256("<nonce>:<counter>").
int PowZeroBits(std::string_view nonce, std::string_view counter);

// A return path that cannot redirect off-site: starts with a single '/'.
bool IsSafeReturnPath(std::string_view path);

std::string Base64UrlEncode(std::string_view data);
bool Base64UrlDecode(std::string_view text, std::string* data);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CHALLENGE_TOKEN_H_
