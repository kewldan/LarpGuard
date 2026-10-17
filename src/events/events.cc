#include "events/events.h"

#include <algorithm>
#include <asio/ip/address.hpp>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "common/hash.h"
#include "common/host.h"
#include "fp/http_fingerprint.h"
#include "fp/http_request.h"

#if BOT_SHIELD_FOXIO
#include "fp/foxio/ja4plus.h"
#endif

namespace bot_shield {
namespace {

constexpr std::size_t kMaxValueSize = 512;
constexpr std::size_t kMaxPathSize = 256;
constexpr std::size_t kMaxSegmentSize = 64;

std::string Clip(std::string_view value) {
  return std::string(value.substr(0, std::min(value.size(), kMaxValueSize)));
}

bool IsDigits(std::string_view text) {
  return !text.empty() && std::ranges::all_of(text, [](char c) {
    return std::isdigit(static_cast<unsigned char>(c)) != 0;
  });
}

bool IsHex(std::string_view text) {
  return !text.empty() && std::ranges::all_of(text, [](char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
  });
}

bool IsUuid(std::string_view segment) {
  if (segment.size() != 36) return false;
  for (std::size_t i = 0; i < segment.size(); ++i) {
    const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
    if (dash != (segment[i] == '-')) return false;
    if (!dash && std::isxdigit(static_cast<unsigned char>(segment[i])) == 0) {
      return false;
    }
  }
  return true;
}

std::string NormalizeSegment(std::string_view segment) {
  if (IsDigits(segment)) return ":n";
  if (IsUuid(segment)) return ":uuid";
  if (segment.size() >= 16 && IsHex(segment)) return ":hex";
  if (segment.size() > kMaxSegmentSize) return ":long";
  return std::string(segment);
}

// Host without port, normalized.
std::string HostOnly(std::string_view authority) {
  if (authority.starts_with('[')) {
    const auto close = authority.find(']');
    return NormalizeHost(authority.substr(
        0, close == std::string_view::npos ? authority.size() : close + 1));
  }
  return NormalizeHost(authority.substr(0, authority.find(':')));
}

void SetIfNotEmpty(nlohmann::json& json, const char* key,
                   std::string_view value) {
  if (!value.empty()) json[key] = Clip(value);
}

}  // namespace

int64_t UnixMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string IpPrefix(const asio::ip::address& address) {
  if (address.is_v4()) {
    auto bytes = address.to_v4().to_bytes();
    bytes[3] = 0;
    return asio::ip::make_address_v4(bytes).to_string() + "/24";
  }
  auto v6 = address.to_v6();
  if (v6.is_v4_mapped()) {
    return IpPrefix(asio::ip::make_address_v4(asio::ip::v4_mapped, v6));
  }
  auto bytes = v6.to_bytes();
  std::fill(bytes.begin() + 6, bytes.end(), 0);
  return asio::ip::make_address_v6(bytes).to_string() + "/48";
}

std::string IpHash(const asio::ip::address& address, std::string_view salt) {
  std::string bytes;
  if (address.is_v4()) {
    const auto v4 = address.to_v4().to_bytes();
    bytes.assign(v4.begin(), v4.end());
  } else {
    const auto v6 = address.to_v6().to_bytes();
    bytes.assign(v6.begin(), v6.end());
  }
  return HmacSha256Hex(salt, bytes, 16);
}

std::string PathGroup(std::string_view target) {
  // Absolute-form targets (proxy requests) keep only the path.
  if (const auto scheme = target.find("://");
      scheme != std::string_view::npos && !target.starts_with('/')) {
    const auto path = target.find('/', scheme + 3);
    target = path == std::string_view::npos ? "/" : target.substr(path);
  }
  target = target.substr(0, target.find_first_of("?#"));
  std::string out;
  std::size_t start = 0;
  while (start <= target.size() && out.size() < kMaxPathSize) {
    const std::size_t end = std::min(target.find('/', start), target.size());
    const std::string_view segment = target.substr(start, end - start);
    if (start > 0) out.push_back('/');
    out += NormalizeSegment(segment);
    if (end == target.size()) break;
    start = end + 1;
  }
  if (out.size() > kMaxPathSize) out.resize(kMaxPathSize);
  return out.empty() ? "/" : out;
}

std::string ConnectionEventJson(const ConnectionRecord& record,
                                const EventSettings& settings,
                                int64_t ended_ms) {
  nlohmann::json json = {
      {"ts_ms", record.started_ms},
      {"instance", settings.instance},
      {"conn_id", record.id},
      {"listener", record.listener},
      {"ip_prefix", IpPrefix(record.peer)},
      {"ip_hash", IpHash(record.peer, settings.ip_salt)},
      {"route", record.route},
      {"reason", record.reason},
      {"duration_ms", std::max<int64_t>(0, ended_ms - record.started_ms)},
      {"bytes_in", record.bytes_in},
      {"bytes_out", record.bytes_out},
      {"requests", record.requests},
  };
  SetIfNotEmpty(json, "sni", record.server_name);
  SetIfNotEmpty(json, "tls_version", record.tls_version);
  SetIfNotEmpty(json, "alpn_offered", record.alpn_offered);
  SetIfNotEmpty(json, "alpn", record.alpn);
  SetIfNotEmpty(json, "ja4", record.ja4);
  SetIfNotEmpty(json, "ja4_r", record.ja4_raw);
  SetIfNotEmpty(json, "tcp_fp", record.tcp_fingerprint);
  SetIfNotEmpty(json, "ja4t", record.ja4t);
  SetIfNotEmpty(json, "h2_fp", record.h2_fingerprint);
  return json.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::string RequestEventJson(const ConnectionRecord& record,
                             const HttpRequest& request, int sequence,
                             const EventSettings& settings, int64_t time_ms) {
  nlohmann::json names = nlohmann::json::array();
  for (const std::string& name : request.header_names) {
    names.push_back(Clip(name));
  }
  std::string pseudo;
  for (const std::string& name : request.pseudo_header_order) {
    if (!pseudo.empty()) pseudo.push_back(',');
    pseudo.push_back(name.size() > 1 ? name[1] : '?');
  }

  nlohmann::json json = {
      {"ts_ms", time_ms},
      {"instance", settings.instance},
      {"conn_id", record.id},
      {"seq", sequence},
      {"ip_prefix", IpPrefix(record.peer)},
      {"ip_hash", IpHash(record.peer, settings.ip_salt)},
      {"http_version", request.version},
      {"method", Clip(request.method)},
      {"host", Clip(HostOnly(request.authority))},
      {"path_group", PathGroup(request.target)},
      {"header_fp", HeaderOrderFingerprint(request)},
      {"header_names", names},
      {"has_cookie", request.HasHeader("cookie")},
      {"has_referer", request.HasHeader("referer")},
  };
#if BOT_SHIELD_FOXIO
  json["ja4h"] = foxio::Ja4h(request);
  SetIfNotEmpty(json, "ja4t", record.ja4t);
#endif
  SetIfNotEmpty(json, "pseudo_order", pseudo);
  SetIfNotEmpty(json, "sni", record.server_name);
  SetIfNotEmpty(json, "ja4", record.ja4);
  SetIfNotEmpty(json, "tcp_fp", record.tcp_fingerprint);
  SetIfNotEmpty(json, "h2_fp", record.h2_fingerprint);
  for (const char* header :
       {"user-agent", "accept", "accept-language", "accept-encoding",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site",
        "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user"}) {
    std::string key(header);
    std::ranges::replace(key, '-', '_');
    SetIfNotEmpty(json, key.c_str(), request.Header(header));
  }
  return json.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace bot_shield
