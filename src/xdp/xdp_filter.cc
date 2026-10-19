#include "xdp/xdp_filter.h"

#include <asio/ip/address.hpp>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "common/network.h"

#if defined(__linux__) && BOT_SHIELD_XDP
#include <linux/bpf.h>      // IWYU pragma: keep
#include <linux/if_link.h>  // IWYU pragma: keep
#include <net/if.h>         // IWYU pragma: keep
#include <sys/syscall.h>    // IWYU pragma: keep
#include <unistd.h>         // IWYU pragma: keep

#include <algorithm>           // IWYU pragma: keep
#include <array>               // IWYU pragma: keep
#include <cerrno>              // IWYU pragma: keep
#include <chrono>              // IWYU pragma: keep
#include <condition_variable>  // IWYU pragma: keep
#include <cstddef>             // IWYU pragma: keep
#include <cstring>             // IWYU pragma: keep
#include <format>              // IWYU pragma: keep
#include <fstream>             // IWYU pragma: keep
#include <map>                 // IWYU pragma: keep
#include <mutex>               // IWYU pragma: keep
#include <set>                 // IWYU pragma: keep
#include <stop_token>          // IWYU pragma: keep
#include <string_view>         // IWYU pragma: keep
#include <system_error>        // IWYU pragma: keep
#include <thread>              // IWYU pragma: keep
#include <utility>             // IWYU pragma: keep
#include <vector>              // IWYU pragma: keep

#include "common/log.h"       // IWYU pragma: keep
#include "common/metrics.h"   // IWYU pragma: keep
#include "xdp/xdp_program.h"  // IWYU pragma: keep
#endif

namespace bot_shield {

void XdpAutoBlocks::Add(const asio::ip::address& address,
                        int64_t expires_unix) {
  Network network;
  if (!Network::Parse(Unmapped(address).to_string(), &network)) return;
  const std::scoped_lock lock(mutex_);
  if (entries_.size() >= 65536) entries_.erase(entries_.begin());
  entries_[network.ToString()] = {network, expires_unix};
}

XdpBlocklist XdpAutoBlocks::Snapshot(int64_t unix_now) {
  const std::scoped_lock lock(mutex_);
  std::erase_if(entries_, [unix_now](const auto& entry) {
    return entry.second.second <= unix_now;
  });
  XdpBlocklist out;
  for (const auto& [key, entry] : entries_) out.push_back(entry);
  return out;
}

#if defined(__linux__) && BOT_SHIELD_XDP
namespace {

// Mirrors struct config in filter.bpf.c.
struct ProgramConfig {
  uint64_t heartbeat_ns;
  uint64_t heartbeat_timeout_ns;
  uint64_t syn_interval_ns;
  uint64_t syn_tolerance_ns;
  uint16_t ports[8];
  uint32_t port_count;
  uint32_t flags;
};
static_assert(sizeof(ProgramConfig) == 56);

constexpr uint32_t kFlagDropInvalid = 1;
constexpr uint32_t kFlagDropFragments = 2;
constexpr uint32_t kFlagAllowUdp = 4;
constexpr uint32_t kStatCount = 8;

struct MapSpec {
  const char* name;
  uint32_t type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t flags;
};

// Mirrors the "maps" section of filter.bpf.c.
constexpr std::array<MapSpec, 5> kMaps = {{
    {"config_map", BPF_MAP_TYPE_ARRAY, 4, sizeof(ProgramConfig), 1, 0},
    {"block_v4", BPF_MAP_TYPE_LPM_TRIE, 8, 8, 65536, BPF_F_NO_PREALLOC},
    {"block_v6", BPF_MAP_TYPE_LPM_TRIE, 20, 8, 65536, BPF_F_NO_PREALLOC},
    {"syn_state", BPF_MAP_TYPE_LRU_HASH, 16, 8, 131072, 0},
    {"stats", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, kStatCount, 0},
}};

int64_t Bpf(int command, bpf_attr* attr) {
  return syscall(__NR_bpf, command, attr, sizeof(*attr));
}

std::string Errno(std::string_view what) {
  return std::format("{}: {}", what, std::system_category().message(errno));
}

// CLOCK_MONOTONIC, the clock of bpf_ktime_get_ns (steady_clock on Linux).
uint64_t MonotonicNs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

int PossibleCpus() {
  std::ifstream file("/sys/devices/system/cpu/possible");
  std::string text;
  std::getline(file, text);
  // "0-7" or "0".
  const std::size_t dash = text.find('-');
  if (dash == std::string::npos) return 1;
  return std::stoi(text.substr(dash + 1)) + 1;
}

// LPM trie key for a network: prefix length (host order) and address.
std::string LpmKey(const Network& network) {
  std::string key;
  uint32_t prefix = 0;
  if (network.v4) {
    prefix = static_cast<uint32_t>(network.prefix - 96);
    key.assign(reinterpret_cast<const char*>(&prefix), 4);
    key.append(reinterpret_cast<const char*>(network.bytes.data()) + 12, 4);
  } else {
    prefix = static_cast<uint32_t>(network.prefix);
    key.assign(reinterpret_cast<const char*>(&prefix), 4);
    key.append(reinterpret_cast<const char*>(network.bytes.data()), 16);
  }
  return key;
}

}  // namespace

bool XdpAvailable() { return true; }

bool XdpFilter::Load(const XdpSettings& settings, std::string* error) {
  settings_ = settings;
  for (const MapSpec& spec : kMaps) {
    bpf_attr attr{};
    attr.map_type = spec.type;
    attr.key_size = spec.key_size;
    attr.value_size = spec.value_size;
    attr.max_entries = spec.max_entries;
    attr.map_flags = spec.flags;
    std::strncpy(attr.map_name, spec.name, sizeof(attr.map_name) - 1);
    const int64_t fd = Bpf(BPF_MAP_CREATE, &attr);
    if (fd < 0) {
      *error = Errno(std::format("xdp: create map {}", spec.name));
      return false;
    }
    maps_[spec.name] = static_cast<int>(fd);
  }
  std::vector<bpf_insn> instructions(kXdpProgramSize / sizeof(bpf_insn));
  std::memcpy(instructions.data(), kXdpProgram, kXdpProgramSize);
  for (std::size_t i = 0; i < kXdpRelocationCount; ++i) {
    const XdpRelocation& relocation = kXdpRelocations[i];
    const auto map = maps_.find(relocation.map);
    if (map == maps_.end() || relocation.instruction >= instructions.size()) {
      *error = std::format("xdp: bad relocation to {}", relocation.map);
      return false;
    }
    instructions[relocation.instruction].src_reg = BPF_PSEUDO_MAP_FD;
    instructions[relocation.instruction].imm = map->second;
  }
  static constexpr char kLicense[] = "Dual MIT/GPL";
  std::string log(std::size_t{64} * 1024, '\0');
  bpf_attr attr{};
  attr.prog_type = BPF_PROG_TYPE_XDP;
  attr.insns = reinterpret_cast<uint64_t>(instructions.data());
  attr.insn_cnt = static_cast<uint32_t>(instructions.size());
  attr.license = reinterpret_cast<uint64_t>(kLicense);
  std::strncpy(attr.prog_name, "larpguard", sizeof(attr.prog_name) - 1);
  int64_t fd = Bpf(BPF_PROG_LOAD, &attr);
  if (fd < 0 && errno != EPERM) {
    // Again with the verifier log, for the error message.
    attr.log_buf = reinterpret_cast<uint64_t>(log.data());
    attr.log_size = static_cast<uint32_t>(log.size());
    attr.log_level = 1;
    fd = Bpf(BPF_PROG_LOAD, &attr);
  }
  if (fd < 0) {
    *error = Errno("xdp: load program");
    const std::string_view verifier(log.data(), std::strlen(log.data()));
    if (!verifier.empty()) {
      *error += "; verifier: " +
                std::string(verifier.substr(
                    verifier.size() > 600 ? verifier.size() - 600 : 0));
    }
    return false;
  }
  program_fd_ = static_cast<int>(fd);
  return WriteConfig(true);
}

bool XdpFilter::Attach(std::string* error) {
  ifindex_ = static_cast<int>(if_nametoindex(settings_.interface.c_str()));
  if (ifindex_ == 0) {
    *error = Errno(std::format("xdp: interface {}", settings_.interface));
    return false;
  }
  const auto try_mode = [this](uint32_t flags) {
    bpf_attr attr{};
    attr.link_create.prog_fd = static_cast<uint32_t>(program_fd_);
    attr.link_create.target_ifindex = static_cast<uint32_t>(ifindex_);
    attr.link_create.attach_type = BPF_XDP;
    attr.link_create.flags = flags;
    const int64_t fd = Bpf(BPF_LINK_CREATE, &attr);
    if (fd >= 0) link_fd_ = static_cast<int>(fd);
    return fd >= 0;
  };
  if ((settings_.mode == "auto" || settings_.mode == "native") &&
      try_mode(XDP_FLAGS_DRV_MODE)) {
    mode_ = "native";
    return true;
  }
  if ((settings_.mode == "auto" || settings_.mode == "generic") &&
      try_mode(XDP_FLAGS_SKB_MODE)) {
    mode_ = "generic";
    return true;
  }
  *error = Errno(std::format("xdp: attach to {} ({})", settings_.interface,
                             settings_.mode));
  return false;
}

std::unique_ptr<XdpFilter> XdpFilter::Start(
    const XdpSettings& settings, std::function<bool()> healthy,
    std::function<XdpBlocklist()> blocklist, std::string* error) {
  std::unique_ptr<XdpFilter> filter(new XdpFilter());
  filter->healthy_ = std::move(healthy);
  filter->blocklist_ = std::move(blocklist);
  if (!filter->Load(settings, error) || !filter->Attach(error)) return nullptr;
  filter->thread_ = std::jthread(
      [raw = filter.get()](const std::stop_token& stop) { raw->Run(stop); });
  return filter;
}

std::unique_ptr<XdpFilter> XdpFilter::LoadForTest(const XdpSettings& settings,
                                                  std::string* error) {
  std::unique_ptr<XdpFilter> filter(new XdpFilter());
  if (!filter->Load(settings, error)) return nullptr;
  return filter;
}

XdpFilter::~XdpFilter() {
  if (thread_.joinable()) {
    thread_.request_stop();
    thread_.join();
  }
  // Closing the link detaches the program.
  if (link_fd_ >= 0) close(link_fd_);
  if (program_fd_ >= 0) close(program_fd_);
  for (const auto& [name, fd] : maps_) close(fd);
}

bool XdpFilter::WriteConfig(bool fresh_heartbeat) {
  ProgramConfig config{};
  const uint64_t now = MonotonicNs();
  config.heartbeat_ns = fresh_heartbeat ? now : 0;
  config.heartbeat_timeout_ns =
      static_cast<uint64_t>(settings_.heartbeat_timeout.count()) *
      1000000000ULL;
  if (settings_.syn_rate > 0) {
    config.syn_interval_ns =
        1000000000ULL / static_cast<uint64_t>(settings_.syn_rate);
    config.syn_tolerance_ns =
        config.syn_interval_ns *
        static_cast<uint64_t>(std::max<int64_t>(settings_.syn_burst, 1) - 1);
  }
  for (std::size_t i = 0; i < settings_.ports.size() && i < 8; ++i) {
    config.ports[i] = settings_.ports[i];
    config.port_count = static_cast<uint32_t>(i + 1);
  }
  config.flags = (settings_.drop_invalid ? kFlagDropInvalid : 0) |
                 (settings_.drop_fragments ? kFlagDropFragments : 0) |
                 (settings_.allow_udp ? kFlagAllowUdp : 0);
  uint32_t key = 0;
  bpf_attr attr{};
  attr.map_fd = static_cast<uint32_t>(maps_["config_map"]);
  attr.key = reinterpret_cast<uint64_t>(&key);
  attr.value = reinterpret_cast<uint64_t>(&config);
  attr.flags = BPF_ANY;
  return Bpf(BPF_MAP_UPDATE_ELEM, &attr) == 0;
}

bool XdpFilter::SyncBlocklist(const XdpBlocklist& blocklist, int64_t unix_now) {
  const std::scoped_lock lock(mutex_);
  const uint64_t mono_now = MonotonicNs();
  std::map<std::string, uint64_t> wanted;
  for (const auto& [network, expires] : blocklist) {
    if (expires != 0 && expires <= unix_now) continue;
    const uint64_t expiry =
        expires == 0 ? UINT64_MAX
                     : mono_now + static_cast<uint64_t>(expires - unix_now) *
                                      1000000000ULL;
    std::string key = (network.v4 ? "4" : "6") + LpmKey(network);
    uint64_t& slot = wanted[key];
    slot = std::max(slot, expiry);
  }
  bool ok = true;
  for (auto it = installed_.begin(); it != installed_.end();) {
    if (wanted.contains(it->first)) {
      ++it;
      continue;
    }
    const std::string key = it->first.substr(1);
    bpf_attr attr{};
    attr.map_fd = static_cast<uint32_t>(
        maps_[it->first[0] == '4' ? "block_v4" : "block_v6"]);
    attr.key = reinterpret_cast<uint64_t>(key.data());
    if (Bpf(BPF_MAP_DELETE_ELEM, &attr) != 0 && errno != ENOENT) ok = false;
    it = installed_.erase(it);
  }
  for (const auto& [tagged, expiry] : wanted) {
    const auto existing = installed_.find(tagged);
    if (existing != installed_.end() && existing->second == expiry) continue;
    const std::string key = tagged.substr(1);
    bpf_attr attr{};
    attr.map_fd = static_cast<uint32_t>(
        maps_[tagged[0] == '4' ? "block_v4" : "block_v6"]);
    attr.key = reinterpret_cast<uint64_t>(key.data());
    attr.value = reinterpret_cast<uint64_t>(&expiry);
    attr.flags = BPF_ANY;
    if (Bpf(BPF_MAP_UPDATE_ELEM, &attr) != 0) {
      ok = false;
      continue;
    }
    installed_[tagged] = expiry;
  }
  return ok;
}

XdpStats XdpFilter::Stats() const {
  XdpStats stats;
  const int cpus = PossibleCpus();
  std::vector<uint64_t> values(static_cast<std::size_t>(cpus));
  const auto read = [&](uint32_t index) {
    uint64_t sum = 0;
    bpf_attr attr{};
    attr.map_fd = static_cast<uint32_t>(maps_.at("stats"));
    attr.key = reinterpret_cast<uint64_t>(&index);
    attr.value = reinterpret_cast<uint64_t>(values.data());
    if (Bpf(BPF_MAP_LOOKUP_ELEM, &attr) == 0) {
      for (const uint64_t value : values) sum += value;
    }
    return sum;
  };
  stats.passed = read(0);
  stats.blocked = read(1);
  stats.syn_rate = read(2);
  stats.invalid = read(3);
  stats.fragment = read(4);
  stats.fail_open = read(5);
  return stats;
}

int XdpFilter::TestRun(const std::string& frame) const {
  bpf_attr attr{};
  attr.test.prog_fd = static_cast<uint32_t>(program_fd_);
  attr.test.data_in = reinterpret_cast<uint64_t>(frame.data());
  attr.test.data_size_in = static_cast<uint32_t>(frame.size());
  attr.test.repeat = 1;
  if (Bpf(BPF_PROG_TEST_RUN, &attr) != 0) return -1;
  return static_cast<int>(attr.test.retval);
}

void XdpFilter::Run(const std::stop_token& stop) {
  std::mutex mutex;
  std::condition_variable_any wake;
  while (!stop.stop_requested()) {
    // A stalled gateway stops the heartbeat: the program fails open.
    WriteConfig(!healthy_ || healthy_());
    if (blocklist_) {
      const auto unix_now =
          std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count();
      if (!SyncBlocklist(blocklist_(), unix_now)) {
        log::Warn("xdp: blocklist update failed");
      }
    }
    const XdpStats stats = Stats();
    Metrics& metrics = GlobalMetrics();
    metrics.xdp_passed.Set(static_cast<int64_t>(stats.passed));
    metrics.xdp_blocked.Set(static_cast<int64_t>(stats.blocked));
    metrics.xdp_syn_rate.Set(static_cast<int64_t>(stats.syn_rate));
    metrics.xdp_invalid.Set(static_cast<int64_t>(stats.invalid));
    metrics.xdp_fragment.Set(static_cast<int64_t>(stats.fragment));
    metrics.xdp_fail_open.Set(static_cast<int64_t>(stats.fail_open));
    std::unique_lock lock(mutex);
    wake.wait_for(lock, stop, std::chrono::seconds(1), [] { return false; });
  }
}

#else  // !(__linux__ && BOT_SHIELD_XDP)

bool XdpAvailable() { return false; }

// The callbacks are moved from in the Linux build; here they are unused.
// NOLINTBEGIN(performance-unnecessary-value-param)
std::unique_ptr<XdpFilter> XdpFilter::Start(const XdpSettings& /*settings*/,
                                            std::function<bool()> /*healthy*/,
                                            std::function<XdpBlocklist()>,
                                            std::string* error) {
  *error = "xdp: not in this build (needs Linux and clang with the BPF target)";
  return nullptr;
}
// NOLINTEND(performance-unnecessary-value-param)

std::unique_ptr<XdpFilter> XdpFilter::LoadForTest(
    const XdpSettings& /*settings*/, std::string* error) {
  *error = "xdp: not in this build";
  return nullptr;
}

XdpFilter::~XdpFilter() = default;
bool XdpFilter::Load(const XdpSettings& /*settings*/, std::string* error) {
  *error = "xdp: not in this build";
  return false;
}
bool XdpFilter::Attach(std::string* error) {
  *error = "xdp: not in this build";
  return false;
}
void XdpFilter::Run(const std::stop_token& /*stop*/) {}
XdpStats XdpFilter::Stats() const { return {}; }
bool XdpFilter::WriteConfig(bool /*fresh_heartbeat*/) { return false; }
bool XdpFilter::SyncBlocklist(const XdpBlocklist& /*blocklist*/,
                              int64_t /*unix_now*/) {
  return false;
}
int XdpFilter::TestRun(const std::string& /*frame*/) const { return -1; }

#endif

}  // namespace bot_shield
