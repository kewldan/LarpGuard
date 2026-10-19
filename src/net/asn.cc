#include "net/asn.h"

#include <arpa/inet.h>
#include <netinet/in.h>  // IWYU pragma: keep (in6_addr on Linux)
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <asio/ip/address.hpp>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace bot_shield {
namespace {

// Large clouds and hosters whose names do not say "hosting".
constexpr std::array<uint32_t, 61> kHostingAsns = {
    13335,   // Cloudflare (incl. WARP)
    14061,   // DigitalOcean
    14618,   // Amazon AES
    15169,   // Google
    16276,   // OVH
    16509,   // Amazon
    19527,   // Google
    20473,   // Vultr (Choopa)
    24940,   // Hetzner
    213230,  // Hetzner Cloud
    8075,    // Microsoft
    8068,    // Microsoft
    8987,    // Amazon
    396982,  // Google Cloud
    63949,   // Akamai Connected Cloud (Linode)
    51167,   // Contabo
    40021,   // Contabo US
    12876,   // Scaleway
    31898,   // Oracle Cloud
    45102,   // Alibaba Cloud
    37963,   // Alibaba (CN)
    132203,  // Tencent Cloud
    45090,   // Tencent
    60781,   // Leaseweb NL
    28753,   // Leaseweb DE
    30633,   // Leaseweb US
    59253,   // Leaseweb Asia
    9009,    // M247
    60068,   // Datacamp (CDN77)
    212238,  // Datacamp
    36352,   // ColoCrossing
    53667,   // FranTech (BuyVM)
    46606,   // Unified Layer
    26496,   // GoDaddy
    398101,  // GoDaddy
    47583,   // Hostinger
    62240,   // Clouvider
    197540,  // netcup
    49981,   // WorldStream
    50673,   // Serverius
    35916,   // Multacom
    8100,    // QuadraNet
    396356,  // Latitude.sh
    54290,   // Hostwinds
    22612,   // Namecheap
    135377,  // UCloud
    55286,   // B2 Net (ServerMania)
    32613,   // iWeb
    32097,   // WholeSale Internet
    7506,    // GMO Internet
    9370,    // Sakura Internet
    4785,    // xTom
    3214,    // xTom
    44477,   // Stark Industries
    210644,  // Aeza
    56971,   // CGI Global (Gcore)
    199524,  // Gcore
    202422,  // G-Core Labs
    61317,   // Hivelocity
    29802,   // Hivelocity
    23470,   // ReliableSite
};

constexpr std::array<std::string_view, 9> kHostingWords = {
    "HOSTING", "DATACENTER", "DATA CENTER", "DATA-CENTER", "VPS",
    "SERVERS", "CLOUD",      "COLOCATION",  "DEDICATED"};

std::string Upper(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return out;
}

bool ParseV4(std::string_view text, uint32_t* out) {
  uint32_t value = 0;
  for (int part = 0; part < 4; ++part) {
    unsigned octet = 0;
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), octet);
    if (error != std::errc() || octet > 255 || end == text.data()) {
      return false;
    }
    value = (value << 8) | octet;
    text.remove_prefix(static_cast<std::size_t>(end - text.data()));
    if (part < 3) {
      if (text.empty() || text.front() != '.') return false;
      text.remove_prefix(1);
    }
  }
  *out = value;
  return text.empty();
}

bool ParseV6(std::string_view text, std::array<uint8_t, 16>* out) {
  char buffer[INET6_ADDRSTRLEN];
  if (text.size() >= sizeof(buffer)) return false;
  std::memcpy(buffer, text.data(), text.size());
  buffer[text.size()] = '\0';
  in6_addr address{};
  if (inet_pton(AF_INET6, buffer, &address) != 1) return false;
  std::memcpy(out->data(), &address, 16);
  return true;
}

}  // namespace

bool IsHostingAs(uint32_t asn, std::string_view org) {
  if (std::ranges::find(kHostingAsns, asn) != kHostingAsns.end()) {
    return true;
  }
  const std::string upper = Upper(org);
  return std::ranges::any_of(kHostingWords, [&upper](std::string_view word) {
    return upper.find(word) != std::string::npos;
  });
}

bool AsnDatabase::Parse(std::string_view tsv, AsnDatabase* out,
                        std::string* error) {
  AsnDatabase db;
  std::unordered_map<uint32_t, uint32_t> index_of;
  std::size_t line_number = 0;
  std::size_t bad = 0;
  while (!tsv.empty()) {
    ++line_number;
    const std::size_t newline = tsv.find('\n');
    std::string_view line = tsv.substr(0, newline);
    tsv.remove_prefix(newline == std::string_view::npos ? tsv.size()
                                                        : newline + 1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) continue;
    std::array<std::string_view, 5> fields;
    std::size_t count = 0;
    while (count < 4) {
      const std::size_t tab = line.find('\t');
      if (tab == std::string_view::npos) break;
      fields[count++] = line.substr(0, tab);
      line.remove_prefix(tab + 1);
    }
    fields[count++] = line;
    uint32_t asn = 0;
    if (count < 4 || std::from_chars(fields[2].data(),
                                     fields[2].data() + fields[2].size(), asn)
                             .ec != std::errc()) {
      ++bad;
      continue;
    }
    if (asn == 0) continue;  // "Not routed".
    auto [it, inserted] =
        index_of.try_emplace(asn, static_cast<uint32_t>(db.ases_.size()));
    if (inserted) {
      As as;
      as.asn = asn;
      as.country = fields[3] == "None" ? "" : std::string(fields[3]);
      as.org = count > 4 ? std::string(fields[4]) : std::string();
      as.hosting = IsHostingAs(asn, as.org);
      db.ases_.push_back(std::move(as));
    }
    const uint32_t as_index = it->second;
    if (fields[0].find(':') == std::string_view::npos) {
      V4Range range{0, 0, as_index};
      if (!ParseV4(fields[0], &range.start) ||
          !ParseV4(fields[1], &range.end) || range.end < range.start) {
        ++bad;
        continue;
      }
      db.v4_.push_back(range);
    } else {
      V6Range range{{}, {}, as_index};
      if (!ParseV6(fields[0], &range.start) ||
          !ParseV6(fields[1], &range.end) || range.end < range.start) {
        ++bad;
        continue;
      }
      db.v6_.push_back(range);
    }
  }
  if (db.v4_.empty() && db.v6_.empty()) {
    *error = std::format("asn: no ranges in {} lines", line_number);
    return false;
  }
  // Bad lines are tolerated in small numbers (upstream data quirks).
  if (bad * 100 > line_number) {
    *error = std::format("asn: {} of {} lines unreadable", bad, line_number);
    return false;
  }
  std::ranges::sort(db.v4_, {}, &V4Range::start);
  std::ranges::sort(db.v6_, {}, &V6Range::start);
  *out = std::move(db);
  return true;
}

AsnInfo AsnDatabase::Info(uint32_t index) const {
  const As& as = ases_[index];
  return AsnInfo{as.asn, as.org, as.country, as.hosting};
}

std::optional<AsnInfo> AsnDatabase::Lookup(
    const asio::ip::address& address) const {
  if (address.is_v4() || (address.is_v6() && address.to_v6().is_v4_mapped())) {
    const uint32_t ip =
        address.is_v4()
            ? address.to_v4().to_uint()
            : asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6())
                  .to_uint();
    // Last range starting at or before ip.
    auto it = std::ranges::upper_bound(v4_, ip, {}, &V4Range::start);
    if (it == v4_.begin()) return std::nullopt;
    --it;
    if (ip > it->end) return std::nullopt;
    return Info(it->as);
  }
  const std::array<uint8_t, 16> ip = address.to_v6().to_bytes();
  auto it = std::ranges::upper_bound(v6_, ip, {}, &V6Range::start);
  if (it == v6_.begin()) return std::nullopt;
  --it;
  if (ip > it->end) return std::nullopt;
  return Info(it->as);
}

}  // namespace bot_shield
