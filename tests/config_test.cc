#include "config/config.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

#include "common/log.h"

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
