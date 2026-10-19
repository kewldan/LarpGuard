#ifndef BOT_SHIELD_COMMON_COMPRESS_H_
#define BOT_SHIELD_COMMON_COMPRESS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bot_shield {

// Decompresses gzip data; fails above `max_size` bytes of output.
bool Gunzip(std::string_view data, std::size_t max_size, std::string* out,
            std::string* error);

// zlib-format (RFC 1950) compression, as PNG IDAT chunks need.
std::string ZlibCompress(std::string_view data);

// CRC-32 (PNG chunks, gzip).
uint32_t Crc32(std::string_view data, uint32_t crc = 0);

}  // namespace bot_shield

#endif  // BOT_SHIELD_COMMON_COMPRESS_H_
