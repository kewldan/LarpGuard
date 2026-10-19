#include "common/compress.h"

// next_in of z_stream is const with ZLIB_CONST.
#define ZLIB_CONST
#include <zlib.h>

#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace bot_shield {

bool Gunzip(std::string_view data, std::size_t max_size, std::string* out,
            std::string* error) {
  z_stream stream{};
  // 16 + MAX_WBITS: gzip header and trailer.
  if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
    *error = "gunzip: init failed";
    return false;
  }
  out->clear();
  stream.next_in = reinterpret_cast<const Bytef*>(data.data());
  stream.avail_in = static_cast<uInt>(data.size());
  char buffer[65536];
  int status = Z_OK;
  while (status != Z_STREAM_END) {
    stream.next_out = reinterpret_cast<Bytef*>(buffer);
    stream.avail_out = sizeof(buffer);
    status = inflate(&stream, Z_NO_FLUSH);
    if (status != Z_OK && status != Z_STREAM_END) {
      *error = std::format("gunzip: {}",
                           stream.msg != nullptr ? stream.msg : "corrupt data");
      inflateEnd(&stream);
      return false;
    }
    out->append(buffer, sizeof(buffer) - stream.avail_out);
    if (out->size() > max_size) {
      *error = "gunzip: output too large";
      inflateEnd(&stream);
      return false;
    }
    if (status == Z_OK && stream.avail_in == 0 && stream.avail_out != 0) {
      *error = "gunzip: truncated data";
      inflateEnd(&stream);
      return false;
    }
  }
  inflateEnd(&stream);
  return true;
}

std::string ZlibCompress(std::string_view data) {
  uLongf size = compressBound(static_cast<uLong>(data.size()));
  std::string out(size, '\0');
  compress2(reinterpret_cast<Bytef*>(out.data()), &size,
            reinterpret_cast<const Bytef*>(data.data()),
            static_cast<uLong>(data.size()), Z_BEST_SPEED);
  out.resize(size);
  return out;
}

uint32_t Crc32(std::string_view data, uint32_t crc) {
  return static_cast<uint32_t>(
      crc32(crc, reinterpret_cast<const Bytef*>(data.data()),
            static_cast<uInt>(data.size())));
}

}  // namespace bot_shield
