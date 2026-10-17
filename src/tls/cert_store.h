#ifndef BOT_SHIELD_TLS_CERT_STORE_H_
#define BOT_SHIELD_TLS_CERT_STORE_H_

#include <asio/ssl/context.hpp>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bot_shield {

// One certificate with its private key, ready to serve.
struct CertEntry {
  // Server-side TLS context holding this certificate and key.
  std::shared_ptr<asio::ssl::context> context;
  // DNS names from the certificate (normalized, may include "*.parent").
  std::vector<std::string> names;
  std::chrono::system_clock::time_point not_after;
};

// Immutable SNI -> certificate index. Built off the hot path and published
// through CertStore.
class CertSnapshot {
 public:
  // Exact name first, then a wildcard for the parent domain.
  std::shared_ptr<const CertEntry> Find(std::string_view server_name) const;

  // Indexes `entry` under each of its names. On a name collision the entry
  // with the later expiry wins.
  void Add(std::shared_ptr<const CertEntry> entry);

  std::size_t certificate_count() const { return certificate_count_; }
  std::size_t name_count() const { return exact_.size() + wildcard_.size(); }

 private:
  using Index =
      std::unordered_map<std::string, std::shared_ptr<const CertEntry>>;

  static void Insert(Index* index, std::string key,
                     const std::shared_ptr<const CertEntry>& entry);

  Index exact_;
  // Keyed by the parent domain: "*.example.com" -> "example.com".
  Index wildcard_;
  std::size_t certificate_count_ = 0;
};

// Builds a server TLS context from PEM data: a leaf certificate optionally
// followed by its chain, and the matching private key.
bool BuildCertEntry(std::string_view cert_pem, std::string_view key_pem,
                    CertEntry* entry, std::string* error);

// Parses Traefik's acme.json (v2/v3 layout: resolver -> Certificates[]).
// Broken certificates are skipped with a warning; only an unreadable document
// is an error.
bool ParseAcmeJson(std::string_view json, CertSnapshot* snapshot,
                   std::vector<std::string>* warnings, std::string* error);

// Holds the current snapshot. Readers get a reference-counted copy, so a
// reload never invalidates certificates of in-flight handshakes.
class CertStore {
 public:
  CertStore();

  std::shared_ptr<const CertSnapshot> snapshot() const;
  void set_snapshot(std::shared_ptr<const CertSnapshot> snapshot);

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<const CertSnapshot> snapshot_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_TLS_CERT_STORE_H_
