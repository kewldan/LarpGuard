#include "tls/cert_store.h"

#include <openssl/base64.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/host.h"

namespace bot_shield {
namespace {

// Server preference order for ALPN.
constexpr std::array<std::string_view, 2> kServerAlpn = {"h2", "http/1.1"};

std::string LastSslError() {
  const uint32_t code = ERR_get_error();
  ERR_clear_error();
  if (code == 0) return "unknown error";
  char buffer[256];
  ERR_error_string_n(code, buffer, sizeof(buffer));
  return buffer;
}

int SelectAlpn(SSL* /*ssl*/, const uint8_t** out, uint8_t* out_len,
               const uint8_t* in, unsigned in_len, void* /*arg*/) {
  for (std::string_view wanted : kServerAlpn) {
    for (unsigned i = 0; i < in_len;) {
      const uint8_t size = in[i];
      if (i + 1 + size > in_len) return SSL_TLSEXT_ERR_NOACK;
      const std::string_view offered(reinterpret_cast<const char*>(in + i + 1),
                                     size);
      if (offered == wanted) {
        *out = in + i + 1;
        *out_len = size;
        return SSL_TLSEXT_ERR_OK;
      }
      i += 1 + size;
    }
  }
  // No common protocol: continue without ALPN (HTTP/1.1 is implied).
  return SSL_TLSEXT_ERR_NOACK;
}

std::vector<std::string> DnsNames(X509* certificate) {
  std::vector<std::string> names;
  auto* general_names = static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr));
  if (general_names == nullptr) return names;
  for (size_t i = 0; i < sk_GENERAL_NAME_num(general_names); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(general_names, i);
    if (name->type != GEN_DNS) continue;
    const ASN1_STRING* value = name->d.dNSName;
    names.push_back(NormalizeHost(std::string_view(
        reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
        static_cast<size_t>(ASN1_STRING_length(value)))));
  }
  GENERAL_NAMES_free(general_names);
  return names;
}

bool DecodeBase64(std::string_view input, std::string* output) {
  size_t max_size = 0;
  if (!EVP_DecodedLength(&max_size, input.size())) return false;
  output->resize(max_size);
  size_t size = 0;
  if (!EVP_DecodeBase64(
          reinterpret_cast<uint8_t*>(output->data()), &size, max_size,
          reinterpret_cast<const uint8_t*>(input.data()), input.size())) {
    return false;
  }
  output->resize(size);
  return true;
}

bool IsUsableName(const std::string& name) {
  const std::string_view host =
      name.starts_with("*.") ? std::string_view(name).substr(2) : name;
  return IsValidHostName(host);
}

}  // namespace

std::shared_ptr<const CertEntry> CertSnapshot::Find(
    std::string_view server_name) const {
  const std::string key(server_name);
  if (auto it = exact_.find(key); it != exact_.end()) return it->second;
  const std::string_view parent = ParentDomain(server_name);
  if (parent.empty()) return nullptr;
  if (auto it = wildcard_.find(std::string(parent)); it != wildcard_.end()) {
    return it->second;
  }
  return nullptr;
}

void CertSnapshot::Add(const std::shared_ptr<const CertEntry>& entry) {
  for (const std::string& name : entry->names) {
    if (name.starts_with("*.")) {
      Insert(&wildcard_, name.substr(2), entry);
    } else {
      Insert(&exact_, name, entry);
    }
  }
  ++certificate_count_;
}

void CertSnapshot::Insert(Index* index, std::string key,
                          const std::shared_ptr<const CertEntry>& entry) {
  auto [it, inserted] = index->try_emplace(std::move(key), entry);
  if (!inserted && it->second->not_after < entry->not_after) {
    it->second = entry;
  }
}

bool BuildCertEntry(std::string_view cert_pem, std::string_view key_pem,
                    CertEntry* entry, std::string* error) {
  bssl::UniquePtr<BIO> cert_bio(BIO_new_mem_buf(
      cert_pem.data(), static_cast<ossl_ssize_t>(cert_pem.size())));
  bssl::UniquePtr<X509> leaf(
      PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  if (!leaf) {
    *error = "certificate: " + LastSslError();
    return false;
  }
  std::vector<bssl::UniquePtr<X509>> chain;
  while (X509* next =
             PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr)) {
    chain.emplace_back(next);
  }
  ERR_clear_error();  // PEM_read_bio_X509 reports the end of input as error.

  bssl::UniquePtr<BIO> key_bio(BIO_new_mem_buf(
      key_pem.data(), static_cast<ossl_ssize_t>(key_pem.size())));
  bssl::UniquePtr<EVP_PKEY> key(
      PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    *error = "private key: " + LastSslError();
    return false;
  }

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  if (!ctx || !SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) ||
      !SSL_CTX_use_certificate(ctx.get(), leaf.get())) {
    *error = "certificate: " + LastSslError();
    return false;
  }
  for (const auto& intermediate : chain) {
    if (!SSL_CTX_add1_chain_cert(ctx.get(), intermediate.get())) {
      *error = "chain: " + LastSslError();
      return false;
    }
  }
  if (!SSL_CTX_use_PrivateKey(ctx.get(), key.get()) ||
      !SSL_CTX_check_private_key(ctx.get())) {
    *error = "private key does not match certificate: " + LastSslError();
    return false;
  }
  SSL_CTX_set_alpn_select_cb(ctx.get(), SelectAlpn, nullptr);

  int64_t not_after = 0;
  if (!ASN1_TIME_to_posix(X509_get0_notAfter(leaf.get()), &not_after)) {
    *error = "certificate: invalid notAfter";
    return false;
  }

  entry->names = DnsNames(leaf.get());
  std::erase_if(entry->names,
                [](const std::string& name) { return !IsUsableName(name); });
  entry->not_after =
      std::chrono::system_clock::time_point(std::chrono::seconds(not_after));
  // asio::ssl::context takes ownership of the native handle.
  entry->context = std::make_shared<asio::ssl::context>(ctx.release());
  return true;
}

bool ParseAcmeJson(std::string_view json, CertSnapshot* snapshot,
                   std::vector<std::string>* warnings, std::string* error) {
  const nlohmann::json root = nlohmann::json::parse(json, nullptr, false);
  if (root.is_discarded() || !root.is_object()) {
    *error = "acme.json: not a JSON object";
    return false;
  }
  for (const auto& [resolver, data] : root.items()) {
    if (!data.is_object()) continue;
    const auto certificates = data.find("Certificates");
    if (certificates == data.end() || certificates->is_null()) continue;
    if (!certificates->is_array()) {
      warnings->push_back(
          std::format("resolver {}: Certificates is not a list", resolver));
      continue;
    }
    for (std::size_t i = 0; i < certificates->size(); ++i) {
      const nlohmann::json& item = (*certificates)[i];
      const std::string where = std::format("resolver {} #{}", resolver, i);
      const auto cert_it = item.find("certificate");
      const auto key_it = item.find("key");
      if (cert_it == item.end() || key_it == item.end() ||
          !cert_it->is_string() || !key_it->is_string()) {
        warnings->push_back(where + ": missing certificate or key");
        continue;
      }
      std::string cert_pem;
      std::string key_pem;
      if (!DecodeBase64(cert_it->get_ref<const std::string&>(), &cert_pem) ||
          !DecodeBase64(key_it->get_ref<const std::string&>(), &key_pem)) {
        warnings->push_back(where + ": invalid base64");
        continue;
      }
      auto entry = std::make_shared<CertEntry>();
      std::string entry_error;
      if (!BuildCertEntry(cert_pem, key_pem, entry.get(), &entry_error)) {
        warnings->push_back(std::format("{}: {}", where, entry_error));
        continue;
      }
      if (entry->names.empty()) {
        warnings->push_back(where + ": certificate has no DNS names");
        continue;
      }
      snapshot->Add(entry);
    }
  }
  return true;
}

CertStore::CertStore() : snapshot_(std::make_shared<CertSnapshot>()) {}

std::shared_ptr<const CertSnapshot> CertStore::snapshot() const {
  std::scoped_lock lock(mutex_);
  return snapshot_;
}

void CertStore::set_snapshot(std::shared_ptr<const CertSnapshot> snapshot) {
  std::scoped_lock lock(mutex_);
  snapshot_ = std::move(snapshot);
}

}  // namespace bot_shield
