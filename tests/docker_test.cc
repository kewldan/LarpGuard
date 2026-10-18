#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "docker/client.h"
#include "docker/labels.h"
#include "ratelimit/limits.h"
#include "score/policy.h"

namespace bot_shield {
namespace {

TEST(DockerClientTest, ParsesContainerList) {
  std::vector<ContainerInfo> containers;
  std::string error;
  ASSERT_TRUE(ParseContainerList(R"([
    {"Id": "abc123def4567890", "Names": ["/shop"],
     "Labels": {"botshield.mode": "enforce", "n": 1}},
    {"Id": "ffff00001111", "Names": [], "Labels": null}
  ])",
                                 &containers, &error))
      << error;
  ASSERT_EQ(containers.size(), 2u);
  EXPECT_EQ(containers[0].name, "shop");
  EXPECT_EQ(containers[0].labels.at("botshield.mode"), "enforce");
  EXPECT_FALSE(containers[0].labels.contains("n"));  // Not a string.
  EXPECT_EQ(containers[1].name, "ffff00001111");
  EXPECT_FALSE(ParseContainerList("{}", &containers, &error));
}

TEST(DockerLabelsTest, TraefikRuleHosts) {
  EXPECT_EQ(TraefikRuleHosts("Host(`a.test`)"),
            std::vector<std::string>{"a.test"});
  EXPECT_EQ(TraefikRuleHosts("Host(`a.test`, `b.test`) || "
                             "(Host(\"c.test\") && PathPrefix(`/api`))"),
            (std::vector<std::string>{"a.test", "b.test", "c.test"}));
  EXPECT_TRUE(TraefikRuleHosts("HostRegexp(`.+`)").empty());
  EXPECT_TRUE(TraefikRuleHosts("HostSNI(`*`)").empty());
  EXPECT_TRUE(TraefikRuleHosts("Host(").empty());
}

TEST(DockerLabelsTest, RateLimitLabel) {
  RateLimitSpec spec;
  std::string error;
  ASSERT_TRUE(ParseRateLimitLabel(
      "rate=20/s burst=40 key=ip,header:x-api-key path=/api/* methods=POST "
      "classes=bot,suspicious",
      &spec, &error))
      << error;
  EXPECT_EQ(spec.count, 20);
  EXPECT_EQ(spec.burst, 40);
  EXPECT_EQ(spec.key, (std::vector<std::string>{"ip", "header:x-api-key"}));
  EXPECT_EQ(spec.paths, std::vector<std::string>{"/api/*"});
  EXPECT_EQ(spec.classes, (std::vector<std::string>{"bot", "suspicious"}));

  RateLimitSpec defaults;
  ASSERT_TRUE(ParseRateLimitLabel("rate=5/m", &defaults, &error));
  EXPECT_EQ(defaults.burst, 5);
  EXPECT_EQ(defaults.key, std::vector<std::string>{"ip"});

  EXPECT_FALSE(ParseRateLimitLabel("burst=5", &spec, &error));
  EXPECT_FALSE(ParseRateLimitLabel("rate=fast", &spec, &error));
  EXPECT_FALSE(ParseRateLimitLabel("rate=5/m speed=1", &spec, &error));
  EXPECT_FALSE(ParseRateLimitLabel("rate=5/m burst=x", &spec, &error));
  EXPECT_FALSE(ParseRateLimitLabel("rate", &spec, &error));
}

ContainerInfo Container(std::string name,
                        std::map<std::string, std::string> labels) {
  ContainerInfo container;
  container.id = name + "-id";
  container.name = std::move(name);
  container.labels = std::move(labels);
  return container;
}

TEST(DockerLabelsTest, BuildsPolicies) {
  const std::vector<ContainerInfo> containers = {
      Container("shop",
                {{"traefik.http.routers.shop.rule", "Host(`Shop.Test`)"},
                 {"botshield.mode", "enforce"},
                 {"botshield.ratelimit.api", "rate=2/m path=/api/*"}}),
      Container("grpc", {{"botshield.hosts", "grpc.test, *.rpc.test"},
                         {"botshield.passthrough", "true"}}),
      Container("blog",
                {{"traefik.http.routers.blog.rule", "Host(`blog.test`)"}}),
      // Conflicts with "shop" (sorted later by name, so it loses).
      Container("zzz",
                {{"botshield.hosts", "shop.test"}, {"botshield.mode", "off"}}),
      Container("broken", {{"botshield.mode", "loud"},
                           {"botshield.hosts", "broken.test"},
                           {"botshield.ratelimit.x", "rate=1/m key=mac"}}),
      Container("nohosts", {{"botshield.mode", "enforce"}}),
  };
  std::vector<std::string> warnings;
  const auto policies = LabelPolicies::Build(containers, &warnings);

  EXPECT_EQ(policies->ModeFor("shop.test"), HostMode::kEnforce);
  EXPECT_FALSE(policies->IsPassthrough("shop.test"));
  EXPECT_TRUE(policies->IsPassthrough("grpc.test"));
  EXPECT_TRUE(policies->IsPassthrough("a.rpc.test"));
  EXPECT_EQ(policies->ModeFor("grpc.test"), std::nullopt);
  // No botshield.* labels: not managed.
  EXPECT_EQ(policies->ModeFor("blog.test"), std::nullopt);
  // Invalid mode is ignored, the host is still known.
  EXPECT_EQ(policies->ModeFor("broken.test"), std::nullopt);
  EXPECT_EQ(policies->rate_limit_count(), 1u);
  EXPECT_EQ(policies->host_count(), 4u);  // shop, grpc, *.rpc, broken.

  const auto has_warning = [&](std::string_view text) {
    return std::ranges::any_of(warnings, [&](const std::string& warning) {
      return warning.find(text) != std::string::npos;
    });
  };
  EXPECT_TRUE(has_warning("container zzz: host shop.test is already"));
  EXPECT_TRUE(has_warning("botshield.mode 'loud'"));
  EXPECT_TRUE(has_warning("unknown key component 'mac'"));
  EXPECT_TRUE(has_warning("container nohosts"));
}

// Serves one canned HTTP response on a unix socket.
class FakeDockerSocket {
 public:
  explicit FakeDockerSocket(std::string response)
      : path_((std::filesystem::temp_directory_path() /
               ("bs-docker-" + std::to_string(::getpid()) + ".sock"))
                  .string()),
        response_(std::move(response)) {
    std::remove(path_.c_str());
    listener_ = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path_.data(), path_.size());
    EXPECT_EQ(
        bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)),
        0);
    EXPECT_EQ(listen(listener_, 1), 0);
    thread_ = std::thread([this] {
      const int fd = accept(listener_, nullptr, nullptr);
      char buffer[4096];
      std::string request;
      while (request.find("\r\n\r\n") == std::string::npos) {
        const ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        request.append(buffer, static_cast<std::size_t>(n));
      }
      request_ = request;
      send(fd, response_.data(), response_.size(), 0);
      close(fd);
    });
  }
  ~FakeDockerSocket() {
    thread_.join();
    close(listener_);
    std::remove(path_.c_str());
  }
  FakeDockerSocket(const FakeDockerSocket&) = delete;
  FakeDockerSocket& operator=(const FakeDockerSocket&) = delete;

  const std::string& path() const { return path_; }
  const std::string& request() const { return request_; }

 private:
  std::string path_;
  std::string response_;
  std::string request_;
  int listener_ = -1;
  std::thread thread_;
};

TEST(DockerClientTest, GetsChunkedResponseOverUnixSocket) {
  std::vector<ContainerInfo> containers;
  std::string error;
  {
    FakeDockerSocket docker(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\n[{\"Id\r\n"
        "16\r\n\":\"x\",\"Names\":[\"/a\"]}]\r\n"
        "0\r\n\r\n");
    ASSERT_TRUE(ListContainers(docker.path(), std::chrono::seconds(2),
                               &containers, &error))
        << error;
    EXPECT_TRUE(docker.request().starts_with("GET /containers/json HTTP/1.1"));
  }
  ASSERT_EQ(containers.size(), 1u);
  EXPECT_EQ(containers[0].name, "a");
}

TEST(DockerClientTest, ReportsErrors) {
  std::string body;
  std::string error;
  EXPECT_FALSE(DockerGet("/nonexistent/docker.sock", "/x",
                         std::chrono::seconds(1), &body, &error));
  EXPECT_NE(error.find("connect"), std::string::npos) << error;
  {
    FakeDockerSocket docker(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
    EXPECT_FALSE(DockerGet(docker.path(), "/containers/json",
                           std::chrono::seconds(2), &body, &error));
    EXPECT_NE(error.find("500"), std::string::npos) << error;
  }
}

}  // namespace
}  // namespace bot_shield
