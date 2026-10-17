#include "tls/client_hello.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/host.h"

namespace bot_shield {
namespace {

constexpr uint8_t kContentTypeHandshake = 22;
constexpr uint8_t kHandshakeTypeClientHello = 1;
constexpr std::size_t kRecordHeaderSize = 5;
constexpr std::size_t kMaxRecordSize = 16384;

constexpr uint16_t kExtServerName = 0;
constexpr uint16_t kExtSupportedGroups = 10;
constexpr uint16_t kExtEcPointFormats = 11;
constexpr uint16_t kExtSignatureAlgorithms = 13;
constexpr uint16_t kExtAlpn = 16;
constexpr uint16_t kExtSupportedVersions = 43;

constexpr uint8_t kServerNameTypeHostName = 0;

// Bounds-checked big-endian reader over a byte span.
class Reader {
 public:
  explicit Reader(std::span<const uint8_t> data) : data_(data) {}

  bool empty() const { return data_.empty(); }
  std::span<const uint8_t> rest() const { return data_; }

  bool ReadU8(uint8_t* value) {
    if (data_.empty()) return false;
    *value = data_[0];
    data_ = data_.subspan(1);
    return true;
  }

  bool ReadU16(uint16_t* value) {
    if (data_.size() < 2) return false;
    *value = static_cast<uint16_t>((unsigned{data_[0]} << 8) | data_[1]);
    data_ = data_.subspan(2);
    return true;
  }

  bool ReadBytes(std::size_t size, std::span<const uint8_t>* bytes) {
    if (data_.size() < size) return false;
    *bytes = data_.first(size);
    data_ = data_.subspan(size);
    return true;
  }

  bool Skip(std::size_t size) {
    std::span<const uint8_t> ignored;
    return ReadBytes(size, &ignored);
  }

  // Reads a vector with an 8- or 16-bit length prefix into a sub-reader.
  bool ReadPrefixed8(Reader* inner) {
    uint8_t size = 0;
    std::span<const uint8_t> bytes;
    if (!ReadU8(&size) || !ReadBytes(size, &bytes)) return false;
    *inner = Reader(bytes);
    return true;
  }

  bool ReadPrefixed16(Reader* inner) {
    uint16_t size = 0;
    std::span<const uint8_t> bytes;
    if (!ReadU16(&size) || !ReadBytes(size, &bytes)) return false;
    *inner = Reader(bytes);
    return true;
  }

 private:
  std::span<const uint8_t> data_;
};

bool ReadU16List(Reader* reader, std::vector<uint16_t>* out) {
  while (!reader->empty()) {
    uint16_t value = 0;
    if (!reader->ReadU16(&value)) return false;
    out->push_back(value);
  }
  return true;
}

bool ParseServerName(Reader body, ClientHello* hello) {
  Reader list(std::span<const uint8_t>{});
  if (!body.ReadPrefixed16(&list) || !body.empty()) return false;
  while (!list.empty()) {
    uint8_t type = 0;
    Reader name(std::span<const uint8_t>{});
    if (!list.ReadU8(&type) || !list.ReadPrefixed16(&name)) return false;
    if (type != kServerNameTypeHostName || !hello->server_name.empty()) {
      continue;
    }
    const std::span<const uint8_t> bytes = name.rest();
    const std::string host = NormalizeHost(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!IsValidHostName(host)) return false;
    hello->server_name = host;
  }
  return true;
}

bool ParseAlpn(Reader body, ClientHello* hello) {
  Reader list(std::span<const uint8_t>{});
  if (!body.ReadPrefixed16(&list) || !body.empty() || list.empty()) {
    return false;
  }
  while (!list.empty()) {
    uint8_t size = 0;
    std::span<const uint8_t> bytes;
    if (!list.ReadU8(&size) || size == 0 || !list.ReadBytes(size, &bytes)) {
      return false;
    }
    hello->alpn.emplace_back(reinterpret_cast<const char*>(bytes.data()),
                             bytes.size());
  }
  return true;
}

bool ParseExtension(uint16_t type, Reader body, ClientHello* hello) {
  switch (type) {
    case kExtServerName:
      return ParseServerName(body, hello);
    case kExtAlpn:
      return ParseAlpn(body, hello);
    case kExtSupportedGroups: {
      Reader list(std::span<const uint8_t>{});
      return body.ReadPrefixed16(&list) && body.empty() &&
             ReadU16List(&list, &hello->supported_groups);
    }
    case kExtSignatureAlgorithms: {
      Reader list(std::span<const uint8_t>{});
      return body.ReadPrefixed16(&list) && body.empty() &&
             ReadU16List(&list, &hello->signature_algorithms);
    }
    case kExtSupportedVersions: {
      Reader list(std::span<const uint8_t>{});
      return body.ReadPrefixed8(&list) && body.empty() &&
             ReadU16List(&list, &hello->supported_versions);
    }
    case kExtEcPointFormats: {
      Reader list(std::span<const uint8_t>{});
      if (!body.ReadPrefixed8(&list) || !body.empty()) return false;
      while (!list.empty()) {
        uint8_t format = 0;
        list.ReadU8(&format);
        hello->ec_point_formats.push_back(format);
      }
      return true;
    }
    default:
      return true;
  }
}

ParseStatus ParseBody(std::span<const uint8_t> body, ClientHello* hello) {
  Reader reader(body);
  Reader session_id(std::span<const uint8_t>{});
  Reader cipher_suites(std::span<const uint8_t>{});
  Reader compression(std::span<const uint8_t>{});
  if (!reader.ReadU16(&hello->legacy_version) || !reader.Skip(32) ||
      !reader.ReadPrefixed8(&session_id) ||
      !reader.ReadPrefixed16(&cipher_suites) ||
      !ReadU16List(&cipher_suites, &hello->cipher_suites) ||
      hello->cipher_suites.empty() || !reader.ReadPrefixed8(&compression) ||
      compression.empty()) {
    return ParseStatus::kInvalid;
  }
  // Extensions are optional in old ClientHellos.
  if (reader.empty()) return ParseStatus::kOk;

  Reader extensions(std::span<const uint8_t>{});
  if (!reader.ReadPrefixed16(&extensions) || !reader.empty()) {
    return ParseStatus::kInvalid;
  }
  while (!extensions.empty()) {
    uint16_t type = 0;
    Reader ext_body(std::span<const uint8_t>{});
    if (!extensions.ReadU16(&type) || !extensions.ReadPrefixed16(&ext_body)) {
      return ParseStatus::kInvalid;
    }
    // RFC 8446 4.2: a type must not appear more than once.
    if (std::ranges::find(hello->extensions, type) != hello->extensions.end()) {
      return ParseStatus::kInvalid;
    }
    hello->extensions.push_back(type);
    if (!ParseExtension(type, ext_body, hello)) return ParseStatus::kInvalid;
  }
  return ParseStatus::kOk;
}

}  // namespace

bool ClientHello::HasAlpn(std::string_view protocol) const {
  return std::ranges::find(alpn, protocol) != alpn.end();
}

ParseStatus ParseClientHello(std::span<const uint8_t> data,
                             ClientHello* hello) {
  *hello = ClientHello{};
  if (data.empty()) return ParseStatus::kNeedMore;
  if (data[0] != kContentTypeHandshake) return ParseStatus::kNotTls;
  if (data.size() >= 2 && data[1] != 3) return ParseStatus::kNotTls;

  // Reassemble the handshake message from consecutive handshake records.
  std::vector<uint8_t> handshake;
  std::size_t offset = 0;
  while (true) {
    if (data.size() - offset < kRecordHeaderSize) break;
    const uint8_t* header = data.data() + offset;
    if (header[0] != kContentTypeHandshake || header[1] != 3) {
      return ParseStatus::kInvalid;
    }
    const std::size_t record_size = (std::size_t{header[3]} << 8) | header[4];
    if (record_size == 0 || record_size > kMaxRecordSize) {
      return ParseStatus::kInvalid;
    }
    if (data.size() - offset - kRecordHeaderSize < record_size) break;
    const uint8_t* fragment = header + kRecordHeaderSize;
    handshake.insert(handshake.end(), fragment, fragment + record_size);
    offset += kRecordHeaderSize + record_size;

    if (handshake.size() < 4) continue;
    if (handshake[0] != kHandshakeTypeClientHello) {
      return ParseStatus::kInvalid;
    }
    const std::size_t message_size = (std::size_t{handshake[1]} << 16) |
                                     (std::size_t{handshake[2]} << 8) |
                                     handshake[3];
    if (message_size > kMaxClientHelloBytes) return ParseStatus::kInvalid;
    if (handshake.size() - 4 >= message_size) {
      return ParseBody(std::span(handshake).subspan(4, message_size), hello);
    }
  }
  return data.size() >= kMaxClientHelloBytes ? ParseStatus::kInvalid
                                             : ParseStatus::kNeedMore;
}

}  // namespace bot_shield
