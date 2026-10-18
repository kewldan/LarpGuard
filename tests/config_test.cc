#include "config/config.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <utility>
#include <vector>

#include "common/log.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

using std::chrono::milliseconds;

TEST(ConfigTest, ParsesDurations) {
  milliseconds value;
  ASSERT_TRUE(ParseDuration("250ms", &value));
  EXPECT_EQ(value, milliseconds(250));
  ASSERT_TRUE(ParseDuration("5s", &value));
  EXPECT_EQ(value, milliseconds(5000));
  ASSERT_TRUE(ParseDuration("2m", &value));
  EXPECT_EQ(value, milliseconds(120000));
  ASSERT_TRUE(ParseDuration("1h", &value));
  EXPECT_EQ(value, milliseconds(3600000));
  EXPECT_FALSE(ParseDuration("5", &value));
  EXPECT_FALSE(ParseDuration("s", &value));
  EXPECT_FALSE(ParseDuration("-5s", &value));
  EXPECT_FALSE(ParseDuration("5 s", &value));
}

TEST(ConfigTest, ParsesEndpoints) {
  Endpoint endpoint;
  ASSERT_TRUE(ParseEndpoint("127.0.0.1:8443", &endpoint));
  EXPECT_EQ(endpoint, (Endpoint{"127.0.0.1", 8443}));
  ASSERT_TRUE(ParseEndpoint("[::1]:443", &endpoint));
  EXPECT_EQ(endpoint, (Endpoint{"::1", 443}));
  EXPECT_EQ(endpoint.ToString(), "[::1]:443");
  ASSERT_TRUE(ParseEndpoint(":80", &endpoint));
  EXPECT_EQ(endpoint, (Endpoint{"0.0.0.0", 80}));
  ASSERT_TRUE(ParseEndpoint("traefik:8443", &endpoint));
  EXPECT_EQ(endpoint.host, "traefik");
  EXPECT_FALSE(ParseEndpoint("127.0.0.1", &endpoint));
  EXPECT_FALSE(ParseEndpoint("127.0.0.1:0", &endpoint));
  EXPECT_FALSE(ParseEndpoint("127.0.0.1:70000", &endpoint));
  EXPECT_FALSE(ParseEndpoint("::1:443", &endpoint));
  EXPECT_FALSE(ParseEndpoint("[::1]443", &endpoint));
}

TEST(ConfigTest, EmptyDocumentKeepsDefaults) {
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig("", &config, &error)) << error;
  EXPECT_EQ(config.listen_https, (Endpoint{"0.0.0.0", 443}));
  EXPECT_TRUE(config.proxy_protocol);
}

TEST(ConfigTest, ParsesFullConfig) {
  const char* yaml = R"(
listen:
  http: ""
  https: "127.0.0.1:10443"
workers: 4
traefik:
  acme_json: /tmp/acme.json
  acme_reload_interval: 500ms
  upstream_https: 127.0.0.1:18443
  upstream_http: 127.0.0.1:18080
  proxy_protocol: false
  tls_verify: true
passthrough_hosts: [GRPC.example.com, "*.raw.example.com"]
non_tls: passthrough
timeouts:
  client_hello: 1s
  tls_handshake: 2s
  upstream_connect: 3s
  idle: 4m
  drain: 5s
max_connections: 1000
metrics:
  listen: ""
log_level: debug
)";
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(yaml, &config, &error)) << error;
  EXPECT_FALSE(config.listen_http.has_value());
  EXPECT_EQ(config.listen_https, (Endpoint{"127.0.0.1", 10443}));
  EXPECT_EQ(config.workers, 4);
  EXPECT_EQ(config.acme_json, "/tmp/acme.json");
  EXPECT_EQ(config.acme_reload_interval, milliseconds(500));
  EXPECT_EQ(config.upstream_https, (Endpoint{"127.0.0.1", 18443}));
  EXPECT_FALSE(config.proxy_protocol);
  EXPECT_TRUE(config.upstream_tls_verify);
  EXPECT_EQ(
      config.passthrough_hosts,
      (std::vector<std::string>{"grpc.example.com", "*.raw.example.com"}));
  EXPECT_EQ(config.non_tls, NonTlsAction::kPassthrough);
  EXPECT_EQ(config.client_hello_timeout, milliseconds(1000));
  EXPECT_EQ(config.idle_timeout, milliseconds(240000));
  EXPECT_EQ(config.max_connections, 1000u);
  EXPECT_FALSE(config.metrics_listen.has_value());
  EXPECT_EQ(config.log_level, log::Level::kDebug);
}

TEST(ConfigTest, ParsesEvents) {
  const char* yaml = R"(
events:
  nats: nats://127.0.0.1:4222
  subject_prefix: bs.ev
  token: secret
  max_queue: 10
  ip_salt: pepper
  requests: false
)";
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(yaml, &config, &error)) << error;
  ASSERT_TRUE(config.events_nats.has_value());
  EXPECT_EQ(*config.events_nats, (Endpoint{"127.0.0.1", 4222}));
  EXPECT_EQ(config.events_subject_prefix, "bs.ev");
  EXPECT_EQ(config.events_token, "secret");
  EXPECT_EQ(config.events_max_queue, 10u);
  EXPECT_EQ(config.events_ip_salt, "pepper");
  EXPECT_FALSE(config.events_requests);

  Config disabled;
  ASSERT_TRUE(ParseConfig("events: {nats: \"\"}\n", &disabled, &error));
  EXPECT_FALSE(disabled.events_nats.has_value());
  EXPECT_FALSE(
      ParseConfig("events: {subject_prefix: \"a.*\"}\n", &disabled, &error));
  EXPECT_FALSE(ParseConfig("events: {max_queue: 0}\n", &disabled, &error));
}

TEST(ConfigTest, ParsesPolicy) {
  const char* yaml = R"(
mode: enforce
policy:
  thresholds: {suspicious: 40, bot: 80}
  actions: {suspicious: block, bot: block}
  block_status: 429
  hosts:
    Shop.Test: shadow
    "*.api.test": enforce
fingerprints:
  library: /etc/bot-shield/fingerprints.yaml
)";
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(yaml, &config, &error)) << error;
  EXPECT_TRUE(config.policy.enforce);
  EXPECT_EQ(config.policy.suspicious_threshold, 40);
  EXPECT_EQ(config.policy.bot_threshold, 80);
  EXPECT_EQ(config.policy.suspicious_action, Action::kBlock);
  EXPECT_EQ(config.policy.block_status, 429);
  ASSERT_EQ(config.policy.host_modes.size(), 2u);
  EXPECT_EQ(config.policy.host_modes[0],
            (std::pair<std::string, bool>{"shop.test", false}));
  EXPECT_EQ(config.fingerprint_library, "/etc/bot-shield/fingerprints.yaml");

  Config bad;
  EXPECT_FALSE(ParseConfig("mode: strict\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("policy: {thresholds: {suspicious: 80, bot: 40}}\n",
                           &bad, &error));
  EXPECT_FALSE(
      ParseConfig("policy: {actions: {bot: challenge}}\n", &bad, &error));
  EXPECT_FALSE(ParseConfig("policy: {block_status: 200}\n", &bad, &error));
  EXPECT_FALSE(
      ParseConfig("policy: {hosts: {\"bad host\": shadow}}\n", &bad, &error));
}

TEST(ConfigTest, ParsesAndValidatesRules) {
  const char* yaml = R"(
rules:
  - name: admin
    when: 'path ~ "/admin*" and class != "human"'
    action: block
  - name: partners
    when: 'cidr("198.51.100.0/24")'
    action: score
    score: -30
)";
  Config config;
  std::string error;
  ASSERT_TRUE(ParseConfig(yaml, &config, &error)) << error;
  ASSERT_EQ(config.rules.size(), 2u);
  EXPECT_EQ(config.rules[1].score, -30);
  EXPECT_FALSE(
      ParseConfig("rules: [{name: x, when: 'hots == \"a\"', "
                  "action: block}]\n",
                  &config, &error));
  EXPECT_NE(error.find("rule 'x'"), std::string::npos) << error;
  EXPECT_FALSE(
      ParseConfig("rules: [{name: x, when: 'true', action: block, "
                  "extra: 1}]\n",
                  &config, &error));
  EXPECT_FALSE(ParseConfig("rules: {a: 1}\n", &config, &error));
}

TEST(ConfigTest, RejectsUnknownKeys) {
  Config config;
  std::string error;
  EXPECT_FALSE(ParseConfig("traefik:\n  acme: /x\n", &config, &error));
  EXPECT_NE(error.find("traefik: unknown key 'acme'"), std::string::npos)
      << error;
  EXPECT_FALSE(ParseConfig("listn: {}\n", &config, &error));
}

TEST(ConfigTest, RejectsBadValues) {
  Config config;
  std::string error;
  EXPECT_FALSE(ParseConfig("timeouts: {idle: 0s}\n", &config, &error));
  EXPECT_FALSE(ParseConfig("workers: -1\n", &config, &error));
  EXPECT_FALSE(ParseConfig("non_tls: drop\n", &config, &error));
  EXPECT_FALSE(
      ParseConfig("passthrough_hosts: [\"bad host\"]\n", &config, &error));
  EXPECT_FALSE(ParseConfig("listen: {https: nope}\n", &config, &error));
  EXPECT_FALSE(ParseConfig("workers: [1\n", &config, &error));
}

}  // namespace
}  // namespace bot_shield
