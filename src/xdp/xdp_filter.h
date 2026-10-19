#ifndef BOT_SHIELD_XDP_XDP_FILTER_H_
#define BOT_SHIELD_XDP_XDP_FILTER_H_

#include <asio/ip/address.hpp>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "common/network.h"

namespace bot_shield {

struct XdpSettings {
  std::string interface;
  // auto (native, else generic) | native | generic.
  std::string mode = "auto";
  std::vector<uint16_t> ports = {80, 443};
  // UDP to the ports is QUIC (http3.enabled); otherwise it is dropped.
  bool allow_udp = false;
  // New TCP connections per second per /24 (IPv4) or /64 (IPv6); 0: off.
  int64_t syn_rate = 0;
  int64_t syn_burst = 1;
  bool drop_invalid = true;
  bool drop_fragments = false;
  // The program passes everything once the gateway has been unhealthy this
  // long (fail-open); the link also goes away with the process.
  std::chrono::seconds heartbeat_timeout{5};
};

struct XdpStats {
  uint64_t passed = 0;
  uint64_t blocked = 0;
  uint64_t syn_rate = 0;
  uint64_t invalid = 0;
  uint64_t fragment = 0;
  uint64_t fail_open = 0;
};

// What the XDP program should drop: networks with an expiry (Unix seconds,
// 0: never). Built from the admin block lists and the gateway's own
// decisions.
using XdpBlocklist = std::vector<std::pair<Network, int64_t>>;

// The XDP pre-filter (docs/architecture.md 11.1, ADR-016): a BPF program on
// the network interface that drops blocklisted sources, SYN floods per
// prefix and malformed packets for the gateway's ports before the kernel's
// TCP stack. Loaded without libbpf; Linux only (BOT_SHIELD_XDP).
class XdpFilter {
 public:
  // `healthy` gates the heartbeat; `blocklist` is polled every second.
  static std::unique_ptr<XdpFilter> Start(
      const XdpSettings& settings, std::function<bool()> healthy,
      std::function<XdpBlocklist()> blocklist, std::string* error);
  // Loads the program without attaching it (tests: BPF_PROG_TEST_RUN).
  static std::unique_ptr<XdpFilter> LoadForTest(const XdpSettings& settings,
                                                std::string* error);
  ~XdpFilter();
  XdpFilter(const XdpFilter&) = delete;
  XdpFilter& operator=(const XdpFilter&) = delete;

  // "native" or "generic" ("" when not attached).
  const std::string& mode() const { return mode_; }
  XdpStats Stats() const;
  // Writes the configuration with a fresh heartbeat (or a stale one).
  bool WriteConfig(bool fresh_heartbeat);
  // Makes the map match `blocklist`.
  bool SyncBlocklist(const XdpBlocklist& blocklist, int64_t unix_now);
  // Runs the program on one Ethernet frame; returns the XDP action
  // (1 drop, 2 pass) or -1.
  int TestRun(const std::string& frame) const;

 private:
  XdpFilter() = default;
  bool Load(const XdpSettings& settings, std::string* error);
  bool Attach(std::string* error);
  void Run(const std::stop_token& stop);

  XdpSettings settings_;
  std::function<bool()> healthy_;
  std::function<XdpBlocklist()> blocklist_;
  std::string mode_;
  std::map<std::string, int> maps_;  // Name -> fd.
  // Unused in builds without XDP.
  [[maybe_unused]] int program_fd_ = -1;
  [[maybe_unused]] int link_fd_ = -1;
  [[maybe_unused]] int ifindex_ = 0;
  // Networks in the map: key bytes (family + prefix) -> expiry ns.
  std::map<std::string, uint64_t> installed_;
  std::mutex mutex_;
  std::jthread thread_;  // Last: joined first.
};

// Addresses the gateway decided to drop at the edge (honeypot hits with
// xdp.block_honeypot), merged into the XDP blocklist. Bounded; thread-safe.
class XdpAutoBlocks {
 public:
  void Add(const asio::ip::address& address, int64_t expires_unix);
  XdpBlocklist Snapshot(int64_t unix_now);

 private:
  std::mutex mutex_;
  std::map<std::string, std::pair<Network, int64_t>> entries_;
};

// Compiled with the embedded program (Linux and clang with BPF).
bool XdpAvailable();

}  // namespace bot_shield

#endif  // BOT_SHIELD_XDP_XDP_FILTER_H_
