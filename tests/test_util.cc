#include "test_util.h"

#include <openssl/base64.h>
#include <openssl/bio.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <nlohmann/json.hpp>
#include <stdexcept>

namespace bot_shield::testing {
namespace {

std::string BioContents(BIO* bio) {
  const uint8_t* data = nullptr;
  size_t size = 0;
  BIO_mem_contents(bio, &data, &size);
  return {reinterpret_cast<const char*>(data), size};
}

void Check(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(what);
}

}  // namespace

TestCertificate MakeCertificate(const std::vector<std::string>& dns_names,
                                int64_t valid_seconds) {
  bssl::UniquePtr<EC_KEY> ec_key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  Check(ec_key && EC_KEY_generate_key(ec_key.get()), "EC key");
  bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
  Check(EVP_PKEY_set1_EC_KEY(key.get(), ec_key.get()), "EVP_PKEY");

  bssl::UniquePtr<X509> cert(X509_new());
  Check(X509_set_version(cert.get(), X509_VERSION_3), "version");
  Check(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1), "serial");
  Check(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) != nullptr,
        "notBefore");
  Check(
      X509_gmtime_adj(X509_getm_notAfter(cert.get()), valid_seconds) != nullptr,
      "notAfter");
  X509_NAME* name = X509_get_subject_name(cert.get());
  const std::string common_name = dns_names.empty() ? "test" : dns_names[0];
  Check(X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_UTF8,
            reinterpret_cast<const uint8_t*>(common_name.data()),
            static_cast<ossl_ssize_t>(common_name.size()), -1, 0),
        "CN");
  Check(X509_set_issuer_name(cert.get(), name), "issuer");
  Check(X509_set_pubkey(cert.get(), key.get()), "pubkey");

  if (!dns_names.empty()) {
    GENERAL_NAMES* names = sk_GENERAL_NAME_new_null();
    for (const std::string& dns : dns_names) {
      GENERAL_NAME* general = GENERAL_NAME_new();
      ASN1_IA5STRING* value = ASN1_IA5STRING_new();
      ASN1_STRING_set(value, dns.data(), static_cast<ossl_ssize_t>(dns.size()));
      GENERAL_NAME_set0_value(general, GEN_DNS, value);
      sk_GENERAL_NAME_push(names, general);
    }
    const bool added = X509_add1_ext_i2d(cert.get(), NID_subject_alt_name,
                                         names, 0, X509V3_ADD_DEFAULT) == 1;
    GENERAL_NAMES_free(names);
    Check(added, "SAN");
  }
  Check(X509_sign(cert.get(), key.get(), EVP_sha256()) > 0, "sign");

  bssl::UniquePtr<BIO> cert_bio(BIO_new(BIO_s_mem()));
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  Check(PEM_write_bio_X509(cert_bio.get(), cert.get()), "PEM cert");
  Check(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0,
                                 nullptr, nullptr),
        "PEM key");
  return {BioContents(cert_bio.get()), BioContents(key_bio.get())};
}

std::string Base64(std::string_view data) {
  size_t size = 0;
  Check(EVP_EncodedLength(&size, data.size()), "base64 length");
  std::string out(size, '\0');
  const size_t written = EVP_EncodeBlock(
      reinterpret_cast<uint8_t*>(out.data()),
      reinterpret_cast<const uint8_t*>(data.data()), data.size());
  out.resize(written);
  return out;
}

std::string MakeAcmeJson(
    const std::vector<std::pair<std::string, TestCertificate>>& certificates) {
  nlohmann::json list = nlohmann::json::array();
  for (const auto& [main, certificate] : certificates) {
    list.push_back({{"domain", {{"main", main}}},
                    {"certificate", Base64(certificate.cert_pem)},
                    {"key", Base64(certificate.key_pem)},
                    {"Store", "default"}});
  }
  nlohmann::json root = {
      {"letsencrypt",
       {{"Account", {{"Email", "test@example.com"}}}, {"Certificates", list}}}};
  return root.dump(2);
}

std::vector<uint8_t> MakeClientHello(std::string_view server_name,
                                     const std::vector<std::string>& alpn) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  if (!server_name.empty()) {
    const std::string name(server_name);
    SSL_set_tlsext_host_name(ssl.get(), name.c_str());
  }
  if (!alpn.empty()) {
    std::vector<uint8_t> wire;
    for (const std::string& protocol : alpn) {
      wire.push_back(static_cast<uint8_t>(protocol.size()));
      wire.insert(wire.end(), protocol.begin(), protocol.end());
    }
    SSL_set_alpn_protos(ssl.get(), wire.data(), wire.size());
  }
  BIO* read_bio = BIO_new(BIO_s_mem());
  BIO* write_bio = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl.get(), read_bio, write_bio);  // SSL owns both.
  SSL_set_connect_state(ssl.get());
  SSL_do_handshake(ssl.get());  // Stops waiting for the ServerHello.
  const std::string bytes = BioContents(write_bio);
  return {bytes.begin(), bytes.end()};
}

}  // namespace bot_shield::testing
