#ifndef BOT_SHIELD_ADMIN_AUDIT_SIGNER_H_
#define BOT_SHIELD_ADMIN_AUDIT_SIGNER_H_

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace bot_shield {

// Signs the console's audit log (ADR-017, п. 5) with an Ed25519 key that
// stays in the gateway: the console asks for a signature of each entry's
// hash over the admin socket and verifies it with the public key, so an
// entry cannot be forged or rewritten by someone who has the console's
// files but not the gateway's (in compose, another container).
class AuditSigner {
 public:
  // The 32-byte seed in `path` (base64url, created with mode 0600 when the
  // file does not exist yet). Null with `error` when it cannot be read or
  // written.
  static std::unique_ptr<AuditSigner> Load(const std::string& path,
                                           std::string* error);
  static std::unique_ptr<AuditSigner> FromSeed(
      const std::array<uint8_t, 32>& seed);

  // base64url of the 32-byte public key, and its short id (16 hex digits
  // of its SHA-256).
  const std::string& public_key() const { return public_key_; }
  const std::string& key_id() const { return key_id_; }

  // base64url signature of "larpguard-audit-v1\n" + `hash` (64 hex
  // digits); false for anything else.
  bool Sign(std::string_view hash, std::string* signature) const;
  bool Verify(std::string_view hash, std::string_view signature) const;

 private:
  AuditSigner() = default;

  std::array<uint8_t, 64> private_key_{};
  std::array<uint8_t, 32> raw_public_key_{};
  std::string public_key_;
  std::string key_id_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_AUDIT_SIGNER_H_
