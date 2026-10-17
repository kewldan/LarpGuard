#ifndef BOT_SHIELD_TESTS_TEST_UTIL_H_
#define BOT_SHIELD_TESTS_TEST_UTIL_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bot_shield::testing {

struct TestCertificate {
  std::string cert_pem;
  std::string key_pem;
};

// Self-signed P-256 certificate with the given DNS SANs.
TestCertificate MakeCertificate(const std::vector<std::string>& dns_names,
                                long valid_seconds = 30L * 24 * 3600);

std::string Base64(std::string_view data);

// acme.json in Traefik's layout with every certificate under one resolver.
std::string MakeAcmeJson(
    const std::vector<std::pair<std::string, TestCertificate>>& certificates);

// A real ClientHello produced by BoringSSL's client.
std::vector<uint8_t> MakeClientHello(std::string_view server_name,
                                     const std::vector<std::string>& alpn);

}  // namespace bot_shield::testing

#endif  // BOT_SHIELD_TESTS_TEST_UTIL_H_
