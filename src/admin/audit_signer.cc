#include "admin/audit_signer.h"

#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#include "challenge/token.h"
#include "common/hash.h"

namespace bot_shield {
namespace {

constexpr std::string_view kDomain = "larpguard-audit-v1\n";

bool IsHash(std::string_view hash) {
  return hash.size() == 64 && std::ranges::all_of(hash, [](char c) {
           return std::isxdigit(static_cast<unsigned char>(c)) != 0 &&
                  std::isupper(static_cast<unsigned char>(c)) == 0;
         });
}

}  // namespace

std::unique_ptr<AuditSigner> AuditSigner::FromSeed(
    const std::array<uint8_t, 32>& seed) {
  std::unique_ptr<AuditSigner> signer(new AuditSigner());
  ED25519_keypair_from_seed(signer->raw_public_key_.data(),
                            signer->private_key_.data(), seed.data());
  const std::string_view raw(
      reinterpret_cast<const char*>(signer->raw_public_key_.data()),
      signer->raw_public_key_.size());
  signer->public_key_ = Base64UrlEncode(raw);
  signer->key_id_ = Sha256Hex(raw, 16);
  return signer;
}

std::unique_ptr<AuditSigner> AuditSigner::Load(const std::string& path,
                                               std::string* error) {
  std::array<uint8_t, 32> seed{};
  std::ifstream in(path);
  if (in) {
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    while (!text.empty() &&
           std::isspace(static_cast<unsigned char>(text.back())) != 0) {
      text.pop_back();
    }
    std::string raw;
    if (!Base64UrlDecode(text, &raw) || raw.size() != seed.size()) {
      *error = std::format("{}: expected a base64url Ed25519 seed", path);
      return nullptr;
    }
    std::ranges::copy(raw, seed.begin());
    return FromSeed(seed);
  }
  // First start: a new key, readable only by the gateway's user.
  RAND_bytes(seed.data(), seed.size());
  const std::string temporary = path + ".tmp";
  {
    std::ofstream out(temporary, std::ios::trunc);
    out << Base64UrlEncode(std::string_view(
               reinterpret_cast<const char*>(seed.data()), seed.size()))
        << '\n';
    if (!out.flush()) {
      *error = std::format("cannot write {}", temporary);
      return nullptr;
    }
  }
  std::error_code ec;
  std::filesystem::permissions(temporary, std::filesystem::perms(0600), ec);
  std::filesystem::rename(temporary, path, ec);
  if (ec) {
    *error = std::format("cannot create {}: {}", path, ec.message());
    return nullptr;
  }
  return FromSeed(seed);
}

bool AuditSigner::Sign(std::string_view hash, std::string* signature) const {
  if (!IsHash(hash)) return false;
  const std::string message = std::string(kDomain) + std::string(hash);
  std::array<uint8_t, 64> out{};
  if (ED25519_sign(out.data(), reinterpret_cast<const uint8_t*>(message.data()),
                   message.size(), private_key_.data()) != 1) {
    return false;
  }
  *signature = Base64UrlEncode(
      std::string_view(reinterpret_cast<const char*>(out.data()), out.size()));
  return true;
}

bool AuditSigner::Verify(std::string_view hash,
                         std::string_view signature) const {
  std::string raw;
  if (!IsHash(hash) || !Base64UrlDecode(signature, &raw) || raw.size() != 64) {
    return false;
  }
  const std::string message = std::string(kDomain) + std::string(hash);
  return ED25519_verify(reinterpret_cast<const uint8_t*>(message.data()),
                        message.size(),
                        reinterpret_cast<const uint8_t*>(raw.data()),
                        raw_public_key_.data()) == 1;
}

}  // namespace bot_shield
