// XDP pre-filter for the gateway's ports (docs/architecture.md 11.1,
// ADR-016). Built with clang -target bpf and loaded by xdp_filter.cc; no
// kernel or libbpf headers, so it builds anywhere clang does.
//
// Per packet to a protected port: blocklisted source -> drop; invalid TCP
// flag combinations -> drop; new connections (SYN) above a rate per /24 or
// /64 -> drop; UDP when HTTP/3 is off -> drop. Everything else, and every
// packet while the gateway's heartbeat is stale (fail-open), passes.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define INLINE static inline __attribute__((always_inline))

enum { XDP_DROP = 1, XDP_PASS = 2 };
enum {
  MAP_ARRAY = 2,
  MAP_PERCPU_ARRAY = 6,
  MAP_LRU_HASH = 9,
  MAP_LPM_TRIE = 11
};

// Map definitions in the legacy "maps" section; the loader creates them
// (the layout is mirrored in xdp_filter.cc).
struct map_def {
  u32 type;
  u32 key_size;
  u32 value_size;
  u32 max_entries;
  u32 flags;
};

struct config {
  u64 heartbeat_ns;          // CLOCK_MONOTONIC of the last heartbeat.
  u64 heartbeat_timeout_ns;  // 0: never fail open.
  u64 syn_interval_ns;       // 1e9 / rate; 0: no SYN limit.
  u64 syn_tolerance_ns;      // interval * (burst - 1).
  u16 ports[8];
  u32 port_count;
  u32 flags;
};

enum {
  FLAG_DROP_INVALID = 1,
  FLAG_DROP_FRAGMENTS = 2,
  FLAG_ALLOW_UDP = 4,
};

struct v4_key {
  u32 prefixlen;
  u8 addr[4];
};
struct v6_key {
  u32 prefixlen;
  u8 addr[16];
};
struct prefix_key {
  u8 family;
  u8 pad[7];
  u8 addr[8];  // /24 or /64.
};

enum {
  STAT_PASSED = 0,
  STAT_BLOCKED = 1,
  STAT_SYN_RATE = 2,
  STAT_INVALID = 3,
  STAT_FRAGMENT = 4,
  STAT_FAIL_OPEN = 5,
  STAT_COUNT = 8
};

struct map_def SEC("maps") config_map = {MAP_ARRAY, 4, sizeof(struct config),
                                         1, 0};
struct map_def SEC("maps") block_v4 = {MAP_LPM_TRIE, sizeof(struct v4_key), 8,
                                       65536, 1};
struct map_def SEC("maps") block_v6 = {MAP_LPM_TRIE, sizeof(struct v6_key), 8,
                                       65536, 1};
struct map_def SEC("maps") syn_state = {MAP_LRU_HASH, sizeof(struct prefix_key),
                                        8, 131072, 0};
struct map_def SEC("maps") stats = {MAP_PERCPU_ARRAY, 4, 8, STAT_COUNT, 0};

static void *(*map_lookup)(void *map, const void *key) = (void *)1;
static long (*map_update)(void *map, const void *key, const void *value,
                          u64 flags) = (void *)2;
static u64 (*ktime_get_ns)(void) = (void *)5;

struct xdp_md {
  u32 data;
  u32 data_end;
  u32 data_meta;
  u32 ingress_ifindex;
  u32 rx_queue_index;
  u32 egress_ifindex;
};

INLINE u16 swap16(u16 v) { return (u16)((v >> 8) | (v << 8)); }

INLINE int count(u32 stat, int verdict) {
  u64 *value = map_lookup(&stats, &stat);
  if (value) *value += 1;
  return verdict;
}

INLINE int protected_port(const struct config *cfg, u16 port) {
#pragma unroll
  for (int i = 0; i < 8; i++) {
    if (i < cfg->port_count && cfg->ports[i] == port) return 1;
  }
  return 0;
}

// GCRA per prefix: at most one SYN per interval, bursts up to tolerance.
INLINE int syn_allowed(const struct config *cfg, struct prefix_key *key,
                       u64 now) {
  if (cfg->syn_interval_ns == 0) return 1;
  u64 *tat = map_lookup(&syn_state, key);
  if (!tat) {
    u64 next = now + cfg->syn_interval_ns;
    map_update(&syn_state, key, &next, 0);
    return 1;
  }
  u64 start = *tat > now ? *tat : now;
  if (start - now > cfg->syn_tolerance_ns) return 0;
  *tat = start + cfg->syn_interval_ns;
  return 1;
}

// TCP flags byte: FIN 1, SYN 2, RST 4, PSH 8, ACK 16, URG 32.
INLINE int invalid_tcp(u8 flags) {
  if (flags == 0) return 1;                      // Null scan.
  if ((flags & 0x03) == 0x03) return 1;          // SYN+FIN.
  if ((flags & 0x06) == 0x06) return 1;          // SYN+RST.
  if ((flags & 0x29) == 0x29 && !(flags & 0x10)) return 1;  // Xmas.
  return 0;
}

SEC("xdp")
int larpguard_xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  u32 zero = 0;
  struct config *cfg = map_lookup(&config_map, &zero);
  if (!cfg) return XDP_PASS;
  u64 now = ktime_get_ns();
  if (cfg->heartbeat_timeout_ns &&
      now - cfg->heartbeat_ns > cfg->heartbeat_timeout_ns) {
    return count(STAT_FAIL_OPEN, XDP_PASS);
  }

  u8 *p = data;
  if ((void *)(p + 14) > data_end) return XDP_PASS;
  u16 proto = *(u16 *)(p + 12);
  u32 offset = 14;
  if (proto == swap16(0x8100) || proto == swap16(0x88a8)) {
    if ((void *)(p + 18) > data_end) return XDP_PASS;
    proto = *(u16 *)(p + 16);
    offset = 18;
  }

  u8 l4 = 0;
  u8 *transport = 0;
  struct prefix_key prefix = {};
  void *blocked = 0;
  if (proto == swap16(0x0800)) {
    u8 *ip = p + offset;
    if ((void *)(ip + 20) > data_end) return XDP_PASS;
    u32 ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20) return XDP_PASS;
    l4 = ip[9];
    if (l4 != 6 && l4 != 17) return XDP_PASS;
    u16 fragment = swap16(*(u16 *)(ip + 6)) & 0x3fff;
    if (fragment) {
      if (cfg->flags & FLAG_DROP_FRAGMENTS) return count(STAT_FRAGMENT, XDP_DROP);
      return XDP_PASS;
    }
    if (ihl > 60) return XDP_PASS;
    transport = ip + ihl;
    struct v4_key key = {32, {ip[12], ip[13], ip[14], ip[15]}};
    blocked = map_lookup(&block_v4, &key);
    prefix.family = 4;
    prefix.addr[0] = ip[12];
    prefix.addr[1] = ip[13];
    prefix.addr[2] = ip[14];
  } else if (proto == swap16(0x86dd)) {
    u8 *ip = p + offset;
    if ((void *)(ip + 40) > data_end) return XDP_PASS;
    l4 = ip[6];
    if (l4 == 44) {  // Fragment header.
      if (cfg->flags & FLAG_DROP_FRAGMENTS) return count(STAT_FRAGMENT, XDP_DROP);
      return XDP_PASS;
    }
    if (l4 != 6 && l4 != 17) return XDP_PASS;
    transport = ip + 40;
    struct v6_key key = {128, {}};
#pragma unroll
    for (int i = 0; i < 16; i++) key.addr[i] = ip[8 + i];
    blocked = map_lookup(&block_v6, &key);
    prefix.family = 6;
#pragma unroll
    for (int i = 0; i < 8; i++) prefix.addr[i] = ip[8 + i];
  } else {
    return XDP_PASS;
  }

  if ((void *)(transport + 4) > data_end) return XDP_PASS;
  u16 port = swap16(*(u16 *)(transport + 2));
  if (!protected_port(cfg, port)) return XDP_PASS;

  if (blocked && *(u64 *)blocked > now) return count(STAT_BLOCKED, XDP_DROP);

  if (l4 == 17) {
    if (!(cfg->flags & FLAG_ALLOW_UDP) && (cfg->flags & FLAG_DROP_INVALID)) {
      return count(STAT_INVALID, XDP_DROP);
    }
    return count(STAT_PASSED, XDP_PASS);
  }
  if ((void *)(transport + 14) > data_end) return XDP_PASS;
  u8 flags = transport[13];
  if ((cfg->flags & FLAG_DROP_INVALID) && invalid_tcp(flags)) {
    return count(STAT_INVALID, XDP_DROP);
  }
  if ((flags & 0x12) == 0x02 && !syn_allowed(cfg, &prefix, now)) {
    return count(STAT_SYN_RATE, XDP_DROP);
  }
  return count(STAT_PASSED, XDP_PASS);
}

char program_license[] SEC("license") = "Dual MIT/GPL";
