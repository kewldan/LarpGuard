#include "crawler/web_bot_auth.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include "common/structured_fields.h"
#include "fp/http_request.h"

namespace bot_shield {
namespace {

// draft-ietf-webbotauth-httpsig-protocol-00, appendix E.2, with the
// Ed25519 test key of RFC 9421 appendix B.1.4.
constexpr std::string_view kKeyX =
    "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
constexpr std::string_view kKeyId =
    "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
constexpr int64_t kNow = 1735690000;

HttpRequest DictionaryRequest() {
  HttpRequest request;
  request.method = "GET";
  request.authority = "example.com";
  request.target = "/";
  request.headers = {
      {"signature-agent", "agent2=\"https://signature-agent.test\""},
      {"signature-input",
       "sig2=(\"@authority\" \"signature-agent\";key=\"agent2\");"
       "created=1735689600;"
       "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";"
       "alg=\"ed25519\";expires=4889289600;"
       "nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLyS"
       "rAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\""},
      {"signature",
       "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl"
       "4e8PhbNZACSanGdhEwYCCg==:"}};
  return request;
}

HttpRequest LegacyRequest() {
  HttpRequest request;
  request.method = "GET";
  request.authority = "example.com";
  request.target = "/";
  request.headers = {
      {"signature-agent", "\"https://signature-agent.test\""},
      {"signature-input",
       "sig2=(\"@authority\" \"signature-agent\");created=1735689600;"
       "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";"
       "alg=\"ed25519\";expires=1735693200;"
       "nonce=\"e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DC"
       "T9RUKAJ0qVkU0mEeLElW1qg==\";tag=\"web-bot-auth\""},
      {"signature",
       "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZD"
       "si6nJKuHxUi/5Syp3rLWBA==:"}};
  return request;
}

std::string Jwks() {
  return std::string(
             R"({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"x","x":")") +
         std::string(kKeyX) + R"("}]})";
}

WebBotAuthLimits LongLived() {
  WebBotAuthLimits limits;
  limits.max_validity_seconds = int64_t{200} * 365 * 86400;
  return limits;
}

TEST(StructuredFieldsTest, ParsesAndSerializes) {
  const auto dictionary = sf::ParseDictionary(
      R"(a=1, b="x\"y";p=?0, c, d=("i" tok;q=2);r=:AQI=:, e=-1.5)");
  ASSERT_TRUE(dictionary);
  ASSERT_EQ(dictionary->size(), 5U);
  EXPECT_EQ(sf::Serialize(*sf::Find(*dictionary, "a")), "1");
  EXPECT_EQ(sf::Serialize(*sf::Find(*dictionary, "b")), "\"x\\\"y\";p=?0");
  EXPECT_EQ(sf::Serialize(*sf::Find(*dictionary, "c")), "?1");
  EXPECT_EQ(sf::Serialize(*sf::Find(*dictionary, "d")),
            "(\"i\" tok;q=2);r=:AQI=:");
  EXPECT_EQ(sf::Find(*dictionary, "d")->inner_list.Param("r")->text,
            std::string("\x01\x02", 2));
  EXPECT_EQ(sf::Serialize(*sf::Find(*dictionary, "e")), "-1.5");
  EXPECT_FALSE(sf::ParseDictionary("a=1,"));
  EXPECT_FALSE(sf::ParseDictionary("A=1"));
  EXPECT_FALSE(sf::ParseDictionary("a=\"unterminated"));
  EXPECT_FALSE(sf::ParseDictionary("a=(1 2"));
  EXPECT_TRUE(sf::ParseItem("\"https://x\""));
  EXPECT_FALSE(sf::ParseItem("\"a\" junk"));
}

TEST(WebBotAuthTest, ThumbprintMatchesTheDraft) {
  std::map<std::string, Ed25519Key> keys;
  std::string error;
  ASSERT_TRUE(ParseJwks(Jwks(), &keys, &error)) << error;
  ASSERT_EQ(keys.size(), 1U);
  EXPECT_EQ(keys.begin()->first, kKeyId);
  EXPECT_FALSE(ParseJwks(R"({"keys":[{"kty":"RSA"}]})", &keys, &error));
  EXPECT_FALSE(ParseJwks("[]", &keys, &error));
}

TEST(WebBotAuthTest, BuildsTheDraftSignatureBase) {
  int invalid = 0;
  const std::vector<WebBotAuthSignature> signatures =
      ParseWebBotAuth(DictionaryRequest(), kNow, LongLived(), &invalid);
  ASSERT_EQ(signatures.size(), 1U);
  EXPECT_EQ(invalid, 0);
  const WebBotAuthSignature& signature = signatures[0];
  EXPECT_EQ(signature.label, "sig2");
  EXPECT_EQ(signature.agent, "signature-agent.test");
  EXPECT_EQ(signature.identifier,
            "https://signature-agent.test/.well-known/"
            "http-message-signatures-directory");
  EXPECT_EQ(signature.keyid, kKeyId);
  EXPECT_EQ(
      signature.base,
      "\"@authority\": example.com\n"
      "\"signature-agent\";key=\"agent2\": "
      "\"https://signature-agent.test\"\n"
      "\"@signature-params\": (\"@authority\" "
      "\"signature-agent\";key=\"agent2\");created=1735689600;"
      "keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";"
      "alg=\"ed25519\";expires=4889289600;"
      "nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PV"
      "VLySrAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\"");

  std::map<std::string, Ed25519Key> keys;
  std::string error;
  ASSERT_TRUE(ParseJwks(Jwks(), &keys, &error));
  EXPECT_TRUE(VerifyEd25519(keys.begin()->second.public_key, signature.base,
                            signature.signature));
  EXPECT_FALSE(VerifyEd25519(keys.begin()->second.public_key,
                             signature.base + "x", signature.signature));
}

TEST(WebBotAuthTest, LegacyFormVerifies) {
  int invalid = 0;
  WebBotAuthLimits limits;  // One-hour signature: within 24 h.
  const std::vector<WebBotAuthSignature> signatures =
      ParseWebBotAuth(LegacyRequest(), kNow, limits, &invalid);
  ASSERT_EQ(signatures.size(), 1U);
  std::map<std::string, Ed25519Key> keys;
  std::string error;
  ASSERT_TRUE(ParseJwks(Jwks(), &keys, &error));
  EXPECT_TRUE(VerifyEd25519(keys.begin()->second.public_key, signatures[0].base,
                            signatures[0].signature));
  // Expired an hour later.
  EXPECT_TRUE(
      ParseWebBotAuth(LegacyRequest(), 1735693200 + 3600, limits, &invalid)
          .empty());
  EXPECT_EQ(invalid, 1);
}

TEST(WebBotAuthTest, RejectsWhatItCannotTrust) {
  int invalid = 0;
  // Default limits: a 100-year signature is a replayable token.
  EXPECT_TRUE(
      ParseWebBotAuth(DictionaryRequest(), kNow, WebBotAuthLimits(), &invalid)
          .empty());
  EXPECT_EQ(invalid, 1);

  // Not covering the agent.
  HttpRequest request = DictionaryRequest();
  request.headers[1].second =
      "sig2=(\"@authority\");created=1735689600;keyid=\"k\";"
      "expires=1735690600;tag=\"web-bot-auth\"";
  invalid = 0;
  EXPECT_TRUE(ParseWebBotAuth(request, kNow, LongLived(), &invalid).empty());
  EXPECT_EQ(invalid, 1);

  // Other tags are not ours, and an http agent is refused.
  request = DictionaryRequest();
  request.headers[1].second.replace(request.headers[1].second.find("web-bot"),
                                    12, "something-else");
  invalid = 0;
  EXPECT_TRUE(ParseWebBotAuth(request, kNow, LongLived(), &invalid).empty());
  EXPECT_EQ(invalid, 0);
  request = DictionaryRequest();
  request.headers[0].second = "agent2=\"http://signature-agent.test\"";
  EXPECT_TRUE(ParseWebBotAuth(request, kNow, LongLived(), &invalid).empty());
  EXPECT_EQ(invalid, 1);
}

TEST(WebBotAuthTest, VerifierFetchesKeysInTheBackground) {
  std::atomic<int> fetches{0};
  std::string served = Jwks();
  WebBotAuthVerifier::Settings settings;
  settings.limits = LongLived();
  WebBotAuthVerifier verifier(
      settings, [&](const std::string& url, const std::stop_token&,
                    std::string* body, int64_t* max_age, std::string* error) {
        ++fetches;
        if (url !=
            "https://signature-agent.test/.well-known/"
            "http-message-signatures-directory") {
          *error = "unexpected url";
          return false;
        }
        *body = served;
        *max_age = 3600;
        return true;
      });
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
  WebBotAuthResult result = verifier.Check(DictionaryRequest(), now);
  EXPECT_EQ(result.status, WebBotAuthStatus::kPending);
  verifier.WaitIdle();
  result = verifier.Check(DictionaryRequest(), now);
  EXPECT_EQ(result.status, WebBotAuthStatus::kVerified);
  EXPECT_EQ(result.agent, "signature-agent.test");
  EXPECT_EQ(fetches, 1);

  // A tampered request fails with the same key.
  HttpRequest tampered = DictionaryRequest();
  tampered.authority = "other.example";
  EXPECT_EQ(verifier.Check(tampered, now).status, WebBotAuthStatus::kInvalid);

  HttpRequest unsigned_request;
  unsigned_request.authority = "example.com";
  EXPECT_EQ(verifier.Check(unsigned_request, now).status,
            WebBotAuthStatus::kNone);
}

}  // namespace
}  // namespace bot_shield
