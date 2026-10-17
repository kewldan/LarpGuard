#include "net/socket_options.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#if defined(__linux__)
#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif
#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif
#endif

namespace bot_shield {

bool SupportsReusePortBalancing() {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

bool EnableReusePort(int fd) {
  const int one = 1;
  return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) == 0;
}

bool EnableSynCapture(int listen_fd) {
#if defined(__linux__)
  const int one = 1;
  return setsockopt(listen_fd, IPPROTO_TCP, TCP_SAVE_SYN, &one, sizeof(one)) ==
         0;
#else
  (void)listen_fd;
  return false;
#endif
}

std::vector<uint8_t> ReadSavedSyn(int fd) {
#if defined(__linux__)
  // IPv6 (40) + TCP with maximum options (60) fits comfortably.
  std::vector<uint8_t> syn(256);
  socklen_t size = static_cast<socklen_t>(syn.size());
  if (getsockopt(fd, IPPROTO_TCP, TCP_SAVED_SYN, syn.data(), &size) != 0) {
    return {};
  }
  syn.resize(size);
  return syn;
#else
  (void)fd;
  return {};
#endif
}

}  // namespace bot_shield
