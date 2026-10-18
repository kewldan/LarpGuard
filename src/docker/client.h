#ifndef BOT_SHIELD_DOCKER_CLIENT_H_
#define BOT_SHIELD_DOCKER_CLIENT_H_

#include <chrono>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {

struct ContainerInfo {
  std::string id;
  std::string name;  // Without the leading '/'.
  std::map<std::string, std::string> labels;
};

// Parses the body of GET /containers/json.
bool ParseContainerList(std::string_view json,
                        std::vector<ContainerInfo>* containers,
                        std::string* error);

// Blocking GET of `path` from the Docker Engine API on a unix socket.
// Returns the response body of a 200 response.
bool DockerGet(const std::string& socket_path, std::string_view path,
               std::chrono::milliseconds timeout, std::string* body,
               std::string* error);

// Running containers with their labels.
bool ListContainers(const std::string& socket_path,
                    std::chrono::milliseconds timeout,
                    std::vector<ContainerInfo>* containers, std::string* error);

}  // namespace bot_shield

#endif  // BOT_SHIELD_DOCKER_CLIENT_H_
