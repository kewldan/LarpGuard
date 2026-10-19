#ifndef BOT_SHIELD_XDP_XDP_PROGRAM_H_
#define BOT_SHIELD_XDP_XDP_PROGRAM_H_

#include <cstddef>

namespace bot_shield {

// An ld_imm64 instruction that references a map by name.
struct XdpRelocation {
  std::size_t instruction;
  const char* map;
};

// src/xdp/filter.bpf.c compiled for BPF, embedded at build time
// (tools/bpf_embed.py); only with BOT_SHIELD_XDP.
extern const unsigned char kXdpProgram[];
extern const std::size_t kXdpProgramSize;
extern const XdpRelocation kXdpRelocations[];
extern const std::size_t kXdpRelocationCount;

}  // namespace bot_shield

#endif  // BOT_SHIELD_XDP_XDP_PROGRAM_H_
