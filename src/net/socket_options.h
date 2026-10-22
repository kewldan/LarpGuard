#ifndef BOT_SHIELD_NET_SOCKET_OPTIONS_H_
#define BOT_SHIELD_NET_SOCKET_OPTIONS_H_

#include <cstdint>
#include <vector>

namespace bot_shield {

// True on platforms where several listeners can share a port with kernel
// load balancing (SO_REUSEPORT on Linux).
bool SupportsReusePortBalancing();

bool EnableReusePort(int fd);

// Asks the kernel to keep the SYN of accepted connections (Linux
// TCP_SAVE_SYN). Returns false where unsupported.
bool EnableSynCapture(int listen_fd);

// Returns the IP+TCP headers of the SYN that opened `fd`, or an empty vector.
// The kernel hands the SYN out once per connection.
std::vector<uint8_t> ReadSavedSyn(int fd);

// The kernel's smoothed round-trip time of a connected TCP socket in
// microseconds (TCP_INFO on Linux, TCP_CONNECTION_INFO on macOS), or -1.
// It measures the path to the peer's TCP stack: a proxy's, when there is
// one.
int64_t TcpRttMicros(int fd);

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_SOCKET_OPTIONS_H_
