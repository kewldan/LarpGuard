#include "docker/client.h"

#include <llhttp.h>
#include <sys/socket.h>
#include <sys/time.h>   // IWYU pragma: keep (timeval)
#include <sys/types.h>  // IWYU pragma: keep (ssize_t on Linux)
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <format>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace bot_shield {
namespace {

constexpr std::size_t kMaxResponse = std::size_t{16} << 20;

// Collects an HTTP/1.1 response (Content-Length or chunked) with llhttp.
struct ResponseParser {
  ResponseParser() {
    llhttp_settings_init(&settings);
    settings.on_body = [](llhttp_t* parser, const char* at, std::size_t size) {
      static_cast<ResponseParser*>(parser->data)->body.append(at, size);
      return 0;
    };
    settings.on_message_complete = [](llhttp_t* parser) {
      static_cast<ResponseParser*>(parser->data)->complete = true;
      return 0;
    };
    llhttp_init(&parser, HTTP_RESPONSE, &settings);
    parser.data = this;
  }

  ResponseParser(const ResponseParser&) = delete;
  ResponseParser& operator=(const ResponseParser&) = delete;

  llhttp_settings_t settings{};
  llhttp_t parser{};
  std::string body;
  bool complete = false;
};

class Socket {
 public:
  Socket() : fd_(socket(AF_UNIX, SOCK_STREAM, 0)) {}
  ~Socket() {
    if (fd_ >= 0) close(fd_);
  }
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  int fd() const { return fd_; }

 private:
  int fd_;
};

std::string Errno(std::string_view what) {
  return std::format("{}: {}", what, std::system_category().message(errno));
}

}  // namespace

bool ParseContainerList(std::string_view json,
                        std::vector<ContainerInfo>* containers,
                        std::string* error) {
  const nlohmann::json root = nlohmann::json::parse(json, nullptr, false);
  if (root.is_discarded() || !root.is_array()) {
    *error = "docker: /containers/json is not a JSON array";
    return false;
  }
  containers->clear();
  for (const nlohmann::json& item : root) {
    if (!item.is_object()) continue;
    ContainerInfo container;
    if (const auto id = item.find("Id"); id != item.end() && id->is_string()) {
      container.id = id->get<std::string>();
    }
    if (const auto names = item.find("Names");
        names != item.end() && names->is_array() && !names->empty() &&
        (*names)[0].is_string()) {
      container.name = (*names)[0].get<std::string>();
      if (container.name.starts_with('/')) container.name.erase(0, 1);
    }
    if (container.name.empty()) container.name = container.id.substr(0, 12);
    if (const auto labels = item.find("Labels");
        labels != item.end() && labels->is_object()) {
      for (const auto& [key, value] : labels->items()) {
        if (value.is_string()) container.labels[key] = value.get<std::string>();
      }
    }
    containers->push_back(std::move(container));
  }
  return true;
}

bool DockerGet(const std::string& socket_path, std::string_view path,
               std::chrono::milliseconds timeout, std::string* body,
               std::string* error) {
  Socket socket;
  if (socket.fd() < 0) {
    *error = Errno("docker: socket");
    return false;
  }
  timeval tv{};
  tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout.count() / 1000);
  tv.tv_usec =
      static_cast<decltype(tv.tv_usec)>((timeout.count() % 1000) * 1000);
  setsockopt(socket.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(socket.fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  if (socket_path.size() >= sizeof(address.sun_path)) {
    *error = "docker: socket path too long";
    return false;
  }
  std::memcpy(address.sun_path, socket_path.data(), socket_path.size());
  if (connect(socket.fd(), reinterpret_cast<sockaddr*>(&address),
              sizeof(address)) != 0) {
    *error = Errno(std::format("docker: connect {}", socket_path));
    return false;
  }

  const std::string request = std::format(
      "GET {} HTTP/1.1\r\nHost: docker\r\nUser-Agent: bot-shield\r\n"
      "Connection: close\r\n\r\n",
      path);
  std::size_t sent = 0;
  while (sent < request.size()) {
    const ssize_t n =
        send(socket.fd(), request.data() + sent, request.size() - sent, 0);
    if (n <= 0) {
      *error = Errno("docker: send");
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }

  ResponseParser response;
  std::size_t received = 0;
  char buffer[16384];
  while (!response.complete) {
    const ssize_t n = recv(socket.fd(), buffer, sizeof(buffer), 0);
    if (n < 0) {
      *error = Errno("docker: recv");
      return false;
    }
    if (n == 0) {
      // Close-delimited body: tell llhttp the message ended.
      llhttp_finish(&response.parser);
      break;
    }
    received += static_cast<std::size_t>(n);
    if (received > kMaxResponse) {
      *error = "docker: response too large";
      return false;
    }
    const llhttp_errno_t parse_error =
        llhttp_execute(&response.parser, buffer, static_cast<std::size_t>(n));
    if (parse_error != HPE_OK) {
      *error = std::format("docker: bad HTTP response ({})",
                           llhttp_errno_name(parse_error));
      return false;
    }
  }
  if (!response.complete) {
    *error = "docker: incomplete response";
    return false;
  }
  if (response.parser.status_code != 200) {
    *error = std::format("docker: GET {} returned {}", path,
                         response.parser.status_code);
    return false;
  }
  *body = std::move(response.body);
  return true;
}

bool ListContainers(const std::string& socket_path,
                    std::chrono::milliseconds timeout,
                    std::vector<ContainerInfo>* containers,
                    std::string* error) {
  std::string body;
  return DockerGet(socket_path, "/containers/json", timeout, &body, error) &&
         ParseContainerList(body, containers, error);
}

}  // namespace bot_shield
