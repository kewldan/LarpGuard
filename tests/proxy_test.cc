#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "proxy/body_rate.h"
#include "proxy/exchange.h"
#include "proxy/http_message.h"

namespace bot_shield {
namespace {

TEST(BodyRateTest, GraceThenOneSecondPerMinRateBytes) {
  using std::chrono::milliseconds;
  BodyRate rate(milliseconds(2000), 1000);
  EXPECT_TRUE(rate.enabled());
  EXPECT_EQ(rate.remaining(), milliseconds(2000));
  EXPECT_FALSE(rate.Charge(milliseconds(1500)));
  rate.Received(500);  // Half a second more.
  EXPECT_EQ(rate.remaining(), milliseconds(1000));
  // Credit never grows above the grace: a fast start buys no slack later.
  rate.Received(1'000'000);
  EXPECT_EQ(rate.remaining(), milliseconds(2000));
  EXPECT_FALSE(rate.Charge(milliseconds(1999)));
  EXPECT_TRUE(rate.Charge(milliseconds(1)));
  EXPECT_TRUE(rate.expired());
}

TEST(BodyRateTest, DisabledAndExempt) {
  BodyRate off;
  EXPECT_FALSE(off.enabled());
  EXPECT_FALSE(off.Charge(std::chrono::hours(1)));
  EXPECT_FALSE(off.expired());
  BodyRate zero(std::chrono::seconds(20), 0);
  EXPECT_FALSE(zero.enabled());
  EXPECT_TRUE(BodyRateExempt("application/grpc"));
  EXPECT_TRUE(BodyRateExempt("application/grpc+proto"));
  EXPECT_FALSE(BodyRateExempt("application/json"));
  EXPECT_FALSE(BodyRateExempt(""));
}

TEST(HttpMessageTest, ReplacesAltSvc) {
  // Traefik's Alt-Svc would send clients past the gateway (ADR-011).
  HeaderList headers = {{"content-type", "text/html"},
                        {"alt-svc", R"(h3=":8443"; ma=60)"}};
  SetAltSvc("", &headers);
  EXPECT_EQ(headers, (HeaderList{{"content-type", "text/html"}}));
  SetAltSvc(R"(h3=":443"; ma=86400)", &headers);
  EXPECT_EQ(headers.back(), (std::pair<std::string, std::string>{
                                "alt-svc", R"(h3=":443"; ma=86400)"}));
}

TEST(HttpMessageTest, FiltersHopByHopAndSpoofableHeaders) {
  const HeaderList input = {
      {"host", "a.test"},
      {"connection", "keep-alive, x-drop"},
      {"keep-alive", "timeout=5"},
      {"x-drop", "1"},
      {"transfer-encoding", "chunked"},
      {"upgrade", "h2c"},
      {"te", "trailers"},
      {"te", "gzip"},
      {"x-forwarded-for", "6.6.6.6"},
      {"forwarded", "for=6.6.6.6"},
      {"x-real-ip", "6.6.6.6"},
      {"x-bot-score", "0"},
      {"user-agent", "ua"},
      {"cookie", "a=1"},
  };
  const HeaderList expected = {
      {"te", "trailers"}, {"user-agent", "ua"}, {"cookie", "a=1"}};
  EXPECT_EQ(FilterRequestHeaders(input), expected);
}

TEST(HttpMessageTest, AddsForwardingHeaders) {
  ClientInfo client;
  client.address = asio::ip::make_address("::ffff:203.0.113.7");
  client.local_port = 443;
  HeaderList headers;
  AddForwardingHeaders(client, "shop.test:8443", &headers);
  EXPECT_EQ(FindHeader(headers, "x-forwarded-for"), "203.0.113.7");
  EXPECT_EQ(FindHeader(headers, "x-real-ip"), "203.0.113.7");
  EXPECT_EQ(FindHeader(headers, "x-forwarded-proto"), "https");
  EXPECT_EQ(FindHeader(headers, "x-forwarded-host"), "shop.test");
  EXPECT_EQ(FindHeader(headers, "x-forwarded-port"), "443");
}

TEST(HttpMessageTest, ResponseBodyRules) {
  EXPECT_TRUE(ResponseHasBody("GET", 200));
  EXPECT_FALSE(ResponseHasBody("HEAD", 200));
  EXPECT_FALSE(ResponseHasBody("GET", 204));
  EXPECT_FALSE(ResponseHasBody("GET", 304));
  EXPECT_FALSE(ResponseHasBody("GET", 101));
}

TEST(HttpMessageTest, FormatsH1ResponseHead) {
  EXPECT_EQ(FormatH1ResponseHead("1.1", 404, {{"content-length", "0"}}),
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
  EXPECT_EQ(ReasonPhrase(299), "OK");
  EXPECT_EQ(ReasonPhrase(599), "Error");
}

TEST(BodyQueueTest, ReadsAcrossChunks) {
  BodyQueue queue;
  const std::string a = "hello ";
  const std::string b = "world";
  queue.Push(std::span(reinterpret_cast<const uint8_t*>(a.data()), a.size()));
  queue.Push(std::span(reinterpret_cast<const uint8_t*>(b.data()), b.size()));
  EXPECT_EQ(queue.size(), 11u);
  std::vector<uint8_t> out(4);
  std::string read;
  while (const std::size_t n = queue.Read(out)) {
    read.append(reinterpret_cast<const char*>(out.data()), n);
  }
  EXPECT_EQ(read, "hello world");
  EXPECT_TRUE(queue.empty());
}

TEST(ExchangeTest, HooksAndFlowControlCredit) {
  Exchange exchange;
  int upstream_wakes = 0;
  int client_wakes = 0;
  std::size_t request_credit = 0;
  std::size_t response_credit = 0;
  exchange.wake_upstream = [&] { ++upstream_wakes; };
  exchange.wake_client = [&] { ++client_wakes; };
  exchange.request_consumed = [&](std::size_t n) { request_credit += n; };
  exchange.response_consumed = [&](std::size_t n) { response_credit += n; };

  const std::string body = "abcdef";
  const auto bytes =
      std::span(reinterpret_cast<const uint8_t*>(body.data()), body.size());
  exchange.PushRequestBody(bytes);
  exchange.EndRequest();
  EXPECT_EQ(upstream_wakes, 2);
  std::vector<uint8_t> out(16);
  EXPECT_EQ(exchange.ReadRequestBody(out), 6u);
  EXPECT_EQ(request_credit, 6u);

  exchange.SetResponse(ProxyResponse{200, {}});
  exchange.PushResponseBody(bytes);
  exchange.EndResponse();
  EXPECT_EQ(client_wakes, 3);
  EXPECT_EQ(exchange.ReadResponseBody(out), 6u);
  EXPECT_EQ(response_credit, 6u);
  EXPECT_EQ(exchange.response_bytes, 6u);
}

TEST(ExchangeTest, LocalResponseIgnoresUpstream) {
  Exchange exchange;
  bool cancelled = false;
  exchange.cancel_upstream = [&] { cancelled = true; };
  exchange.RespondLocally(403, "no\n");
  EXPECT_TRUE(cancelled);
  EXPECT_TRUE(exchange.local);
  EXPECT_EQ(exchange.response.status, 403);
  EXPECT_EQ(FindHeader(exchange.response.headers, "content-length"), "3");
  // A late upstream response must not replace the local one.
  exchange.SetResponse(ProxyResponse{200, {}});
  exchange.FailUpstream();
  EXPECT_EQ(exchange.response.status, 403);
  EXPECT_FALSE(exchange.upstream_failed);
}

TEST(ExchangeTest, CancelFromClientDropsClientHooks) {
  Exchange exchange;
  int wakes = 0;
  bool cancelled = false;
  exchange.wake_client = [&] { ++wakes; };
  exchange.cancel_upstream = [&] { cancelled = true; };
  exchange.CancelFromClient();
  EXPECT_TRUE(cancelled);
  exchange.FailUpstream();
  EXPECT_EQ(wakes, 0);
}

// Received body bytes go back to the upstream window however the exchange
// ends: read, discarded by a cancel, or replaced by a local answer. A lost
// credit starves the pooled upstream connection for every client.
TEST(ExchangeTest, UnreadBodyCreditsTheUpstream) {
  const std::vector<uint8_t> body(100, 'x');
  {
    Exchange exchange;
    std::size_t credited = 0;
    exchange.response_consumed = [&](std::size_t n) { credited += n; };
    exchange.SetResponse(ProxyResponse{200, {}});
    exchange.PushResponseBody(body);
    std::vector<uint8_t> out(30);
    EXPECT_EQ(exchange.ReadResponseBody(out), 30U);
    EXPECT_EQ(credited, 30U);
    exchange.CancelFromClient();
    EXPECT_EQ(credited, 100U);
  }
  {
    Exchange exchange;
    std::size_t credited = 0;
    exchange.response_consumed = [&](std::size_t n) { credited += n; };
    exchange.SetResponse(ProxyResponse{200, {}});
    exchange.PushResponseBody(body);
    exchange.RespondLocally(502, "bad gateway\n");
    EXPECT_EQ(credited, 100U);
    // The local body is not upstream data.
    std::vector<uint8_t> out(64);
    EXPECT_GT(exchange.ReadResponseBody(out), 0U);
    EXPECT_EQ(credited, 100U);
  }
}

}  // namespace
}  // namespace bot_shield
