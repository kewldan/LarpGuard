#include <gtest/gtest.h>
#include <nghttp2/nghttp2.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fp/h1_tap.h"
#include "fp/h2_tap.h"
#include "fp/http_fingerprint.h"
#include "fp/http_request.h"

#if BOT_SHIELD_FOXIO
#include "fp/foxio/ja4plus.h"
#endif

namespace bot_shield {
namespace {

std::span<const uint8_t> Bytes(std::string_view text) {
  return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

// --- HTTP/1.x -------------------------------------------------------------

TEST(H1TapTest, ReportsHeadersInWireOrderAndCase) {
  std::vector<HttpRequest> requests;
  H1Tap tap([&](HttpRequest&& r) { requests.push_back(std::move(r)); });
  tap.Feed(Bytes(
      "GET /items/42?q=1 HTTP/1.1\r\nHost: Shop.Test\r\nUser-Agent: curl/8\r\n"
      "accept: */*\r\nCookie: b=2; a=1\r\n\r\n"));
  ASSERT_EQ(requests.size(), 1u);
  const HttpRequest& r = requests[0];
  EXPECT_EQ(r.version, "1.1");
  EXPECT_EQ(r.method, "GET");
  EXPECT_EQ(r.target, "/items/42?q=1");
  EXPECT_EQ(r.authority, "Shop.Test");
  EXPECT_EQ(r.header_names, (std::vector<std::string>{"Host", "User-Agent",
                                                      "accept", "Cookie"}));
  EXPECT_EQ(r.Header("user-agent"), "curl/8");
  EXPECT_TRUE(r.HasHeader("cookie"));
  EXPECT_TRUE(r.pseudo_header_order.empty());
}

TEST(H1TapTest, HandlesSplitInputBodiesAndPipelining) {
  std::vector<HttpRequest> requests;
  H1Tap tap([&](HttpRequest&& r) { requests.push_back(std::move(r)); });
  const std::string stream =
      "POST /form HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"
      "GET /next HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
      "3\r\nabc\r\n0\r\n\r\n"
      "HEAD / HTTP/1.0\r\n\r\n";
  for (const char c : stream) tap.Feed(Bytes(std::string_view(&c, 1)));
  ASSERT_EQ(requests.size(), 3u);
  EXPECT_EQ(requests[0].method, "POST");
  EXPECT_EQ(requests[1].target, "/next");
  EXPECT_EQ(requests[2].version, "1.0");
  EXPECT_TRUE(tap.active());
}

TEST(H1TapTest, StopsAtUpgradeAndOnGarbage) {
  int count = 0;
  H1Tap websocket([&](HttpRequest&&) { ++count; });
  websocket.Feed(
      Bytes("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\n"
            "Upgrade: websocket\r\n\r\n\x81\x05hello"));
  EXPECT_EQ(count, 1);
  EXPECT_FALSE(websocket.active());

  H1Tap garbage([&](HttpRequest&&) { ++count; });
  garbage.Feed(Bytes("\x16\x03\x01 not http\r\n\r\n"));
  EXPECT_FALSE(garbage.active());
  EXPECT_EQ(count, 1);
}

TEST(H1TapTest, StopsOnOversizedHeaders) {
  int count = 0;
  H1Tap tap([&](HttpRequest&&) { ++count; });
  tap.Feed(Bytes("GET / HTTP/1.1\r\nX-Big: "));
  const std::string chunk(4096, 'x');
  for (int i = 0; i < 20 && tap.active(); ++i) tap.Feed(Bytes(chunk));
  EXPECT_FALSE(tap.active());
  EXPECT_EQ(count, 0);
}

// --- HTTP/2 ---------------------------------------------------------------

std::string Frame(uint8_t type, uint8_t flags, uint32_t stream,
                  std::string_view payload) {
  std::string frame;
  const auto size = static_cast<uint32_t>(payload.size());
  frame.push_back(static_cast<char>(size >> 16));
  frame.push_back(static_cast<char>((size >> 8) & 0xFF));
  frame.push_back(static_cast<char>(size & 0xFF));
  frame.push_back(static_cast<char>(type));
  frame.push_back(static_cast<char>(flags));
  for (int shift = 24; shift >= 0; shift -= 8) {
    frame.push_back(static_cast<char>((stream >> shift) & 0xFF));
  }
  frame += payload;
  return frame;
}

std::string Settings(const std::vector<std::pair<uint16_t, uint32_t>>& items) {
  std::string payload;
  for (const auto& [id, value] : items) {
    payload.push_back(static_cast<char>(id >> 8));
    payload.push_back(static_cast<char>(id & 0xFF));
    for (int shift = 24; shift >= 0; shift -= 8) {
      payload.push_back(static_cast<char>((value >> shift) & 0xFF));
    }
  }
  return Frame(0x4, 0, 0, payload);
}

std::string WindowUpdate(uint32_t increment) {
  std::string payload;
  for (int shift = 24; shift >= 0; shift -= 8) {
    payload.push_back(static_cast<char>((increment >> shift) & 0xFF));
  }
  return Frame(0x8, 0, 0, payload);
}

class HpackEncoder {
 public:
  HpackEncoder() { nghttp2_hd_deflate_new(&deflater_, 4096); }
  ~HpackEncoder() { nghttp2_hd_deflate_del(deflater_); }
  HpackEncoder(const HpackEncoder&) = delete;
  HpackEncoder& operator=(const HpackEncoder&) = delete;

  std::string Encode(
      const std::vector<std::pair<std::string, std::string>>& headers) {
    std::vector<nghttp2_nv> nva;
    nva.reserve(headers.size());
    for (const auto& [name, value] : headers) {
      nva.push_back(
          {reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())),
           reinterpret_cast<uint8_t*>(const_cast<char*>(value.data())),
           name.size(), value.size(), NGHTTP2_NV_FLAG_NONE});
    }
    std::string out(nghttp2_hd_deflate_bound(deflater_, nva.data(), nva.size()),
                    '\0');
    const auto size = nghttp2_hd_deflate_hd2(
        deflater_, reinterpret_cast<uint8_t*>(out.data()), out.size(),
        nva.data(), nva.size());
    out.resize(static_cast<std::size_t>(size));
    return out;
  }

 private:
  nghttp2_hd_deflater* deflater_ = nullptr;
};

std::vector<std::pair<std::string, std::string>> ChromeHeaders() {
  return {
      {":method", "GET"},
      {":authority", "shop.test"},
      {":scheme", "https"},
      {":path", "/p/1"},
      {"user-agent", "Mozilla/5.0"},
      {"accept-language", "en-US,en;q=0.9"},
  };
}

TEST(H2TapTest, BuildsAkamaiFingerprintAndRequests) {
  std::vector<HttpRequest> requests;
  H2Tap tap([&](HttpRequest&& r) { requests.push_back(std::move(r)); });
  HpackEncoder encoder;

  std::string stream = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  stream += Settings({{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}});
  stream += WindowUpdate(15663105);
  // END_STREAM | END_HEADERS
  stream += Frame(0x1, 0x5, 1, encoder.Encode(ChromeHeaders()));
  // DATA frame on stream 3 is skipped.
  stream += Frame(0x0, 0x1, 3, std::string(100, 'd'));
  // Second request reuses the dynamic table.
  auto second = ChromeHeaders();
  second[3].second = "/p/2";
  stream += Frame(0x1, 0x5, 5, encoder.Encode(second));

  for (std::size_t i = 0; i < stream.size(); i += 7) {
    tap.Feed(Bytes(std::string_view(stream).substr(i, 7)));
  }
  ASSERT_EQ(requests.size(), 2u);
  EXPECT_EQ(tap.fingerprint(),
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
  EXPECT_EQ(requests[0].version, "2");
  EXPECT_EQ(requests[0].method, "GET");
  EXPECT_EQ(requests[0].authority, "shop.test");
  EXPECT_EQ(requests[1].target, "/p/2");
  EXPECT_EQ(requests[1].header_names,
            (std::vector<std::string>{"user-agent", "accept-language"}));
  EXPECT_EQ(
      requests[1].pseudo_header_order,
      (std::vector<std::string>{":method", ":authority", ":scheme", ":path"}));
  EXPECT_TRUE(tap.active());
}

TEST(H2TapTest, ContinuationPaddingAndPriority) {
  std::vector<HttpRequest> requests;
  H2Tap tap([&](HttpRequest&& r) { requests.push_back(std::move(r)); });
  HpackEncoder encoder;
  const std::string block = encoder.Encode(ChromeHeaders());

  std::string stream = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  stream += Settings({{3, 1000}});
  // PRIORITY frame: stream 3 depends on 0, weight 201 (encoded 200).
  stream += Frame(0x2, 0, 3, std::string("\x00\x00\x00\x00\xC8", 5));
  // HEADERS with PADDED and PRIORITY flags, block split into CONTINUATION.
  std::string payload;
  payload.push_back(2);                               // pad length
  payload += std::string("\x80\x00\x00\x00\xFF", 5);  // priority
  payload += block.substr(0, 5);
  payload += std::string(2, '\0');  // padding
  stream += Frame(0x1, 0x8 | 0x20 | 0x1, 1, payload);
  stream += Frame(0x9, 0x4, 1, block.substr(5));

  tap.Feed(Bytes(stream));
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].target, "/p/1");
  EXPECT_EQ(tap.fingerprint(), "3:1000|00|3:0:0:201|m,a,s,p");
}

TEST(H2TapTest, StopsOnBadPrefaceOrInterruptedHeaderBlock) {
  H2Tap bad_preface([](HttpRequest&&) {});
  bad_preface.Feed(Bytes("GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
  EXPECT_FALSE(bad_preface.active());

  H2Tap interrupted([](HttpRequest&&) {});
  HpackEncoder encoder;
  std::string stream = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  stream +=
      Frame(0x1, 0x0, 1, encoder.Encode(ChromeHeaders()));  // no END_HEADERS
  stream += Settings({{1, 4096}});
  interrupted.Feed(Bytes(stream));
  EXPECT_FALSE(interrupted.active());
}

// --- Fingerprints ---------------------------------------------------------

TEST(HttpFingerprintTest, HeaderOrderFingerprint) {
  HttpRequest request;
  request.version = "1.1";
  request.header_names = {"Host", "User-Agent"};
  const std::string fp = HeaderOrderFingerprint(request);
  EXPECT_TRUE(fp.starts_with("1.1:2:")) << fp;
  EXPECT_EQ(fp.size(), 6u + 12u);
  request.header_names = {"User-Agent", "Host"};
  EXPECT_NE(HeaderOrderFingerprint(request), fp);
  request.header_names = {"host", "user-agent"};
  EXPECT_NE(HeaderOrderFingerprint(request), fp);
}

#if BOT_SHIELD_FOXIO
TEST(HttpFingerprintTest, Ja4h) {
  std::vector<HttpRequest> requests;
  H1Tap tap([&](HttpRequest&& r) { requests.push_back(std::move(r)); });
  tap.Feed(
      Bytes("GET / HTTP/1.1\r\nHost: a\r\nAccept-Language: en-US,en;q=0.9\r\n"
            "Referer: https://a/\r\nCookie: z=1; a=2\r\n\r\n"));
  ASSERT_EQ(requests.size(), 1u);
  const std::string ja4h = foxio::Ja4h(requests[0]);
  // get, 1.1, cookie, referer, 2 headers (Host, Accept-Language), "enus".
  EXPECT_TRUE(ja4h.starts_with("ge11cr02enus_")) << ja4h;
  EXPECT_EQ(ja4h.size(), 12u + 3u * 13u);

  HttpRequest bare;
  bare.method = "POST";
  bare.version = "2";
  EXPECT_EQ(foxio::Ja4h(bare),
            "po20nn000000_000000000000_000000000000_000000000000");
}
#endif

}  // namespace
}  // namespace bot_shield
