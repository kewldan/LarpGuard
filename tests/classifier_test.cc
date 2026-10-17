#include "net/classifier.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "config/config.h"
#include "test_util.h"
#include "tls/cert_store.h"
#include "tls/client_hello.h"

namespace bot_shield {
namespace {

using ::bot_shield::testing::MakeCertificate;

class ClassifierTest : public ::testing::Test {
 protected:
  void SetUp() override {
    for (const char* name : {"site.test", "grpc.test"}) {
      const auto certificate = MakeCertificate({name});
      auto entry = std::make_shared<CertEntry>();
      std::string error;
      ASSERT_TRUE(BuildCertEntry(certificate.cert_pem, certificate.key_pem,
                                 entry.get(), &error));
      certificates_.Add(entry);
    }
  }

  static ClientHello Hello(std::string server_name,
                           std::vector<std::string> alpn = {}) {
    ClientHello hello;
    hello.server_name = std::move(server_name);
    hello.alpn = std::move(alpn);
    return hello;
  }

  RouteDecision Classify(const ClientHello& hello,
                         ParseStatus status = ParseStatus::kOk) const {
    return classifier_.Classify(status, hello, certificates_);
  }

  CertSnapshot certificates_;
  Classifier classifier_{{"grpc.test", "*.raw.test"}, NonTlsAction::kReject};
};

TEST_F(ClassifierTest, TerminatesKnownHost) {
  const RouteDecision decision = Classify(Hello("site.test", {"h2"}));
  EXPECT_EQ(decision.route, Route::kTerminate);
  EXPECT_EQ(decision.reason, RouteReason::kCertificate);
  EXPECT_NE(decision.certificate, nullptr);
}

TEST_F(ClassifierTest, PassesAcmeTlsAlpnThrough) {
  const RouteDecision decision = Classify(Hello("site.test", {"acme-tls/1"}));
  EXPECT_EQ(decision.route, Route::kPassthrough);
  EXPECT_EQ(decision.reason, RouteReason::kAcmeTlsAlpn);
}

TEST_F(ClassifierTest, PassesUnknownOrMissingServerNameThrough) {
  EXPECT_EQ(Classify(Hello("")).reason, RouteReason::kNoServerName);
  const RouteDecision decision = Classify(Hello("unknown.test"));
  EXPECT_EQ(decision.route, Route::kPassthrough);
  EXPECT_EQ(decision.reason, RouteReason::kNoCertificate);
}

TEST_F(ClassifierTest, PolicyOverridesCertificate) {
  const RouteDecision decision = Classify(Hello("grpc.test"));
  EXPECT_EQ(decision.route, Route::kPassthrough);
  EXPECT_EQ(decision.reason, RouteReason::kPassthroughPolicy);
  EXPECT_EQ(Classify(Hello("a.raw.test")).reason,
            RouteReason::kPassthroughPolicy);
}

TEST_F(ClassifierTest, RejectsInvalidAndNonTls) {
  EXPECT_EQ(Classify(Hello(""), ParseStatus::kInvalid).route, Route::kReject);
  const RouteDecision decision = Classify(Hello(""), ParseStatus::kNotTls);
  EXPECT_EQ(decision.route, Route::kReject);
  EXPECT_EQ(decision.reason, RouteReason::kNotTls);
}

TEST_F(ClassifierTest, NonTlsPassthroughWhenConfigured) {
  const Classifier classifier({}, NonTlsAction::kPassthrough);
  const RouteDecision decision =
      classifier.Classify(ParseStatus::kNotTls, Hello(""), certificates_);
  EXPECT_EQ(decision.route, Route::kPassthrough);
  EXPECT_EQ(decision.reason, RouteReason::kNotTls);
}

}  // namespace
}  // namespace bot_shield
