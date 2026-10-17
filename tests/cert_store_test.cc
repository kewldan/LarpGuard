#include "tls/cert_store.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "test_util.h"

namespace bot_shield {
namespace {

using ::bot_shield::testing::MakeAcmeJson;
using ::bot_shield::testing::MakeCertificate;

TEST(CertStoreTest, BuildsEntryWithNamesAndExpiry) {
  const auto certificate = MakeCertificate({"Example.com", "*.example.com"});
  CertEntry entry;
  std::string error;
  ASSERT_TRUE(
      BuildCertEntry(certificate.cert_pem, certificate.key_pem, &entry, &error))
      << error;
  EXPECT_EQ(entry.names,
            (std::vector<std::string>{"example.com", "*.example.com"}));
  EXPECT_GT(entry.not_after, std::chrono::system_clock::now());
  ASSERT_NE(entry.context, nullptr);
}

TEST(CertStoreTest, RejectsMismatchedKey) {
  const auto a = MakeCertificate({"a.test"});
  const auto b = MakeCertificate({"b.test"});
  CertEntry entry;
  std::string error;
  EXPECT_FALSE(BuildCertEntry(a.cert_pem, b.key_pem, &entry, &error));
  EXPECT_NE(error.find("does not match"), std::string::npos) << error;
}

TEST(CertStoreTest, ParsesAcmeJsonAndLooksUpNames) {
  const std::string json = MakeAcmeJson({
      {"a.test", MakeCertificate({"a.test", "www.a.test"})},
      {"*.w.test", MakeCertificate({"*.w.test"})},
  });
  CertSnapshot snapshot;
  std::vector<std::string> warnings;
  std::string error;
  ASSERT_TRUE(ParseAcmeJson(json, &snapshot, &warnings, &error)) << error;
  EXPECT_TRUE(warnings.empty());
  EXPECT_EQ(snapshot.certificate_count(), 2u);

  EXPECT_NE(snapshot.Find("a.test"), nullptr);
  EXPECT_NE(snapshot.Find("www.a.test"), nullptr);
  EXPECT_EQ(snapshot.Find("a.test"), snapshot.Find("www.a.test"));
  EXPECT_EQ(snapshot.Find("b.test"), nullptr);

  // A wildcard covers exactly one label and not the parent itself.
  EXPECT_NE(snapshot.Find("x.w.test"), nullptr);
  EXPECT_EQ(snapshot.Find("w.test"), nullptr);
  EXPECT_EQ(snapshot.Find("y.x.w.test"), nullptr);
}

TEST(CertStoreTest, LaterExpiryWinsOnDuplicateNames) {
  const auto short_lived = MakeCertificate({"dup.test"}, 3600);
  const auto long_lived =
      MakeCertificate({"dup.test"}, int64_t{90} * 24 * 3600);
  CertSnapshot snapshot;
  std::vector<std::string> warnings;
  std::string error;
  ASSERT_TRUE(ParseAcmeJson(
      MakeAcmeJson({{"dup.test", long_lived}, {"dup.test", short_lived}}),
      &snapshot, &warnings, &error));
  const auto entry = snapshot.Find("dup.test");
  ASSERT_NE(entry, nullptr);
  EXPECT_GT(entry->not_after,
            std::chrono::system_clock::now() + std::chrono::hours(24 * 30));
}

TEST(CertStoreTest, SkipsBrokenCertificatesWithWarning) {
  std::string json = MakeAcmeJson({{"ok.test", MakeCertificate({"ok.test"})}});
  // Append a second resolver with a broken entry.
  json.pop_back();
  while (json.back() == '\n' || json.back() == ' ') json.pop_back();
  json +=
      R"(, "other": {"Certificates": [{"certificate": "!!!", "key": ""}]}})";

  CertSnapshot snapshot;
  std::vector<std::string> warnings;
  std::string error;
  ASSERT_TRUE(ParseAcmeJson(json, &snapshot, &warnings, &error)) << error;
  EXPECT_EQ(snapshot.certificate_count(), 1u);
  EXPECT_EQ(warnings.size(), 1u);
}

TEST(CertStoreTest, NullCertificatesAreFine) {
  CertSnapshot snapshot;
  std::vector<std::string> warnings;
  std::string error;
  EXPECT_TRUE(ParseAcmeJson(R"({"le": {"Account": {}, "Certificates": null}})",
                            &snapshot, &warnings, &error));
  EXPECT_EQ(snapshot.certificate_count(), 0u);
}

TEST(CertStoreTest, RejectsInvalidJson) {
  CertSnapshot snapshot;
  std::vector<std::string> warnings;
  std::string error;
  EXPECT_FALSE(ParseAcmeJson("{\"le\": ", &snapshot, &warnings, &error));
  EXPECT_FALSE(error.empty());
}

TEST(CertStoreTest, StorePublishesSnapshots) {
  CertStore store;
  ASSERT_NE(store.snapshot(), nullptr);
  EXPECT_EQ(store.snapshot()->certificate_count(), 0u);
  auto snapshot = std::make_shared<CertSnapshot>();
  CertEntry entry;
  std::string error;
  const auto certificate = MakeCertificate({"s.test"});
  ASSERT_TRUE(BuildCertEntry(certificate.cert_pem, certificate.key_pem, &entry,
                             &error));
  snapshot->Add(std::make_shared<CertEntry>(std::move(entry)));
  const auto old_snapshot = store.snapshot();
  store.set_snapshot(snapshot);
  EXPECT_NE(store.snapshot()->Find("s.test"), nullptr);
  EXPECT_EQ(old_snapshot->Find("s.test"), nullptr);
}

}  // namespace
}  // namespace bot_shield
