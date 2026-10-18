#include "proxy/h1_server.h"

#include <llhttp.h>

#include <algorithm>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/this_coro.hpp>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/metrics.h"
#include "fp/http_request.h"
#include "net/watchdog.h"
#include "proxy/exchange.h"
#include "proxy/http_message.h"
#include "proxy/proxy_hooks.h"
#include "proxy/transport.h"
#include "proxy/upstream_pool.h"

namespace bot_shield {
namespace {

// Used by `co_await (a && b)`; clang-tidy does not see operator lookups.
// NOLINTNEXTLINE(misc-unused-using-decls)
using asio::experimental::awaitable_operators::operator&&;

constexpr std::size_t kReadChunk = std::size_t{16} * 1024;
constexpr std::size_t kMaxHeadBytes = std::size_t{64} * 1024;
constexpr auto kHeadTimeout = std::chrono::seconds(30);
constexpr std::string_view kBadGateway = "bad gateway\n";

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

bool ContainsToken(std::string_view list, std::string_view token) {
  const std::string lower = Lowercase(list);
  std::size_t start = 0;
  while (start <= lower.size()) {
    const std::size_t end = std::min(lower.find(',', start), lower.size());
    std::string_view item = std::string_view(lower).substr(start, end - start);
    while (!item.empty() && item.front() == ' ') item.remove_prefix(1);
    while (!item.empty() && item.back() == ' ') item.remove_suffix(1);
    if (item == token) return true;
    start = end + 1;
  }
  return false;
}

std::span<const uint8_t> Bytes(std::string_view text) {
  return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

// Copies `from` -> `to` until either side ends; used for upgraded
// connections. Every read touches the idle watchdog.
asio::awaitable<void> Relay(Transport& from, Transport& to, Watchdog& idle,
                            std::function<void(std::size_t)> on_bytes) {
  std::vector<uint8_t> buffer(kReadChunk);
  while (true) {
    auto [ec, n] = co_await from.ReadSome(buffer);
    if (ec || n == 0) break;
    idle.Touch();
    if (co_await to.WriteAll(std::span(buffer.data(), n))) break;
    if (on_bytes) on_bytes(n);
  }
  from.Close();
  to.Close();
}

}  // namespace

std::shared_ptr<H1ServerConnection> H1ServerConnection::Create(
    std::unique_ptr<Transport> transport, UpstreamPool* pool, ClientInfo client,
    ProxyHooks hooks, const ProxySettings& settings) {
  return std::shared_ptr<H1ServerConnection>(
      new H1ServerConnection(std::move(transport), pool, std::move(client),
                             std::move(hooks), settings));
}

H1ServerConnection::H1ServerConnection(std::unique_ptr<Transport> transport,
                                       UpstreamPool* pool, ClientInfo client,
                                       ProxyHooks hooks,
                                       const ProxySettings& settings)
    : transport_(std::move(transport)),
      pool_(pool),
      client_(std::move(client)),
      hooks_(std::move(hooks)),
      settings_(settings),
      reader_wake_(transport_->executor()),
      response_wake_(transport_->executor()) {
  llhttp_settings_init(&parser_settings_);
  parser_settings_.on_message_begin = &OnMessageBegin;
  parser_settings_.on_method = &OnMethod;
  parser_settings_.on_url = &OnUrl;
  parser_settings_.on_header_field = &OnHeaderField;
  parser_settings_.on_header_value = &OnHeaderValue;
  parser_settings_.on_header_value_complete = &OnHeaderValueComplete;
  parser_settings_.on_headers_complete = &OnHeadersComplete;
  parser_settings_.on_body = &OnBody;
  parser_settings_.on_message_complete = &OnMessageComplete;
  llhttp_init(&parser_, HTTP_REQUEST, &parser_settings_);
  parser_.data = this;
}

H1ServerConnection& H1ServerConnection::Self(llhttp_t* parser) {
  return *static_cast<H1ServerConnection*>(parser->data);
}

int H1ServerConnection::OnMessageBegin(llhttp_t* parser) {
  H1ServerConnection& self = Self(parser);
  self.method_.clear();
  self.url_.clear();
  self.field_.clear();
  self.value_.clear();
  self.raw_headers_.clear();
  self.header_bytes_ = 0;
  self.headers_complete_ = false;
  self.message_complete_ = false;
  self.upgrade_ = false;
  self.expect_continue_ = false;
  self.exchange_.reset();
  return 0;
}

int H1ServerConnection::OnMethod(llhttp_t* parser, const char* at,
                                 std::size_t size) {
  H1ServerConnection& self = Self(parser);
  self.method_.append(at, size);
  self.header_bytes_ += size;
  return 0;
}

int H1ServerConnection::OnUrl(llhttp_t* parser, const char* at,
                              std::size_t size) {
  H1ServerConnection& self = Self(parser);
  self.url_.append(at, size);
  self.header_bytes_ += size;
  if (self.header_bytes_ > kMaxHeadBytes) {
    self.headers_too_large_ = true;
    return -1;
  }
  return 0;
}

int H1ServerConnection::OnHeaderField(llhttp_t* parser, const char* at,
                                      std::size_t size) {
  H1ServerConnection& self = Self(parser);
  self.field_.append(at, size);
  self.header_bytes_ += size;
  if (self.header_bytes_ > kMaxHeadBytes) {
    self.headers_too_large_ = true;
    return -1;
  }
  return 0;
}

int H1ServerConnection::OnHeaderValue(llhttp_t* parser, const char* at,
                                      std::size_t size) {
  H1ServerConnection& self = Self(parser);
  self.value_.append(at, size);
  self.header_bytes_ += size;
  if (self.header_bytes_ > kMaxHeadBytes) {
    self.headers_too_large_ = true;
    return -1;
  }
  return 0;
}

int H1ServerConnection::OnHeaderValueComplete(llhttp_t* parser) {
  H1ServerConnection& self = Self(parser);
  self.raw_headers_.emplace_back(std::move(self.field_),
                                 std::move(self.value_));
  self.field_.clear();
  self.value_.clear();
  return 0;
}

int H1ServerConnection::OnHeadersComplete(llhttp_t* parser) {
  H1ServerConnection& self = Self(parser);
  self.headers_complete_ = true;
  self.http_minor_ = parser->http_major == 1 ? parser->http_minor : 1;
  self.upgrade_ = parser->upgrade != 0;
  if (!self.upgrade_) self.StartExchange();
  return 0;
}

int H1ServerConnection::OnBody(llhttp_t* parser, const char* at,
                               std::size_t size) {
  H1ServerConnection& self = Self(parser);
  if (self.exchange_) {
    self.exchange_->PushRequestBody(
        std::span(reinterpret_cast<const uint8_t*>(at), size));
  }
  return 0;
}

int H1ServerConnection::OnMessageComplete(llhttp_t* parser) {
  H1ServerConnection& self = Self(parser);
  self.message_complete_ = true;
  if (self.exchange_ && !self.exchange_->request_ended) {
    self.exchange_->EndRequest();
  }
  // Stop here: a pipelined next request waits until this one is answered.
  return HPE_PAUSED;
}

void H1ServerConnection::StartExchange() {
  auto exchange = std::make_shared<Exchange>();
  exchange->started_ms = SteadyMillis();

  HttpRequest& observed = exchange->observed;
  observed.version = std::format("1.{}", http_minor_);
  observed.method = method_;
  observed.target = url_;
  HeaderList lowercase;
  for (const auto& [name, value] : raw_headers_) {
    observed.header_names.push_back(name);
    lowercase.emplace_back(Lowercase(name), value);
  }
  observed.headers = lowercase;

  ProxyRequest& request = exchange->request;
  request.method = method_;
  request.path = url_;
  request.authority = std::string(FindHeader(lowercase, "host"));
  // Absolute-form target (http://host/path).
  if (const auto scheme = url_.find("://");
      scheme != std::string::npos && !url_.starts_with('/')) {
    const auto path = url_.find('/', scheme + 3);
    request.authority =
        url_.substr(scheme + 3, path == std::string::npos ? std::string::npos
                                                          : path - scheme - 3);
    request.path = path == std::string::npos ? "/" : url_.substr(path);
  }
  if (request.authority.empty()) request.authority = client_.server_name;
  observed.authority = request.authority;

  const std::string_view connection = FindHeader(lowercase, "connection");
  keep_alive_ = http_minor_ >= 1 ? !ContainsToken(connection, "close")
                                 : ContainsToken(connection, "keep-alive");
  expect_continue_ =
      Lowercase(FindHeader(lowercase, "expect")) == "100-continue";

  HeaderList forwarded = FilterRequestHeaders(lowercase);
  std::erase_if(forwarded,
                [](const auto& header) { return header.first == "expect"; });
  AddForwardingHeaders(client_, request.authority, &forwarded);
  request.headers = std::move(forwarded);

  const bool has_body =
      (parser_.flags & F_CHUNKED) != 0 ||
      ((parser_.flags & F_CONTENT_LENGTH) != 0 && parser_.content_length > 0);
  exchange->request_ended = !has_body;

  std::weak_ptr<H1ServerConnection> weak = weak_from_this();
  exchange->wake_client = [weak] {
    if (auto self = weak.lock()) self->response_wake_.Notify();
  };
  exchange->request_consumed = [weak](std::size_t) {
    if (auto self = weak.lock()) self->reader_wake_.Notify();
  };
  exchange_ = exchange;

  if (request.method == "CONNECT") {
    exchange->RespondLocally(405, "method not allowed\n");
    return;
  }
  if (hooks_.on_request) hooks_.on_request(*exchange);
  if (!exchange->local) pool_->Dispatch(client_.server_name, exchange);
}

bool H1ServerConnection::Execute() {
  if (buffer_.empty()) return true;
  const llhttp_errno_t error =
      llhttp_execute(&parser_, buffer_.data(), buffer_.size());
  std::size_t consumed = buffer_.size();
  if (error == HPE_PAUSED || error == HPE_PAUSED_UPGRADE) {
    consumed = static_cast<std::size_t>(llhttp_get_error_pos(&parser_) -
                                        buffer_.data());
    if (error == HPE_PAUSED) {
      llhttp_resume(&parser_);
    } else {
      llhttp_resume_after_upgrade(&parser_);
    }
  } else if (error != HPE_OK) {
    return false;
  }
  buffer_.erase(0, consumed);
  return true;
}

asio::awaitable<bool> H1ServerConnection::ReadMore() {
  auto executor = co_await asio::this_coro::executor;
  ScopedWatchdog idle(executor, settings_.idle_timeout,
                      [this] { transport_->Close(); });
  std::vector<uint8_t> chunk(kReadChunk);
  auto [ec, n] = co_await transport_->ReadSome(chunk);
  if (ec || n == 0) co_return false;
  const std::span<const uint8_t> data(chunk.data(), n);
  if (hooks_.on_client_bytes) hooks_.on_client_bytes(data);
  buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
  co_return true;
}

asio::awaitable<bool> H1ServerConnection::Write(std::string_view data) {
  if (write_failed_) co_return false;
  if (co_await transport_->WriteAll(Bytes(data))) {
    write_failed_ = true;
    transport_->Close();
    co_return false;
  }
  if (hooks_.on_bytes_to_client) hooks_.on_bytes_to_client(data.size());
  co_return true;
}

void H1ServerConnection::Report(const Exchange& exchange) const {
  if (exchange.local) {
    GlobalMetrics().local_responses.Inc();
  } else {
    GlobalMetrics().proxied_requests.Inc();
  }
  if (hooks_.on_done) hooks_.on_done(exchange);
}

asio::awaitable<void> H1ServerConnection::RespondError(int status) {
  const std::string body = std::format("{}\n", ReasonPhrase(status));
  HeaderList headers = LocalResponse(status, body.size()).headers;
  headers.emplace_back("connection", "close");
  co_await Write(FormatH1ResponseHead("1.1", status, headers) + body);
  GlobalMetrics().local_responses.Inc();
}

asio::awaitable<void> H1ServerConnection::WriteResponse(
    std::shared_ptr<Exchange> exchange) {
  auto self = shared_from_this();
  if (expect_continue_ && !exchange->local) {
    co_await Write("HTTP/1.1 100 Continue\r\n\r\n");
  }
  while (!exchange->response_started && !exchange->upstream_failed &&
         !write_failed_) {
    co_await response_wake_.Wait();
  }
  if (!exchange->response_started) exchange->RespondLocally(502, kBadGateway);

  const std::string& method = exchange->request.method;
  const int status = exchange->response.status;
  const bool has_body = ResponseHasBody(method, status);
  HeaderList headers = FilterResponseHeaders(exchange->response.headers);
  const bool has_length = !FindHeader(headers, "content-length").empty();
  bool chunked = false;
  if (has_body && !has_length) {
    if (http_minor_ >= 1) {
      chunked = true;
      headers.emplace_back("transfer-encoding", "chunked");
    } else {
      keep_alive_ = false;  // Body ends with the connection.
    }
  }
  if (!keep_alive_) {
    headers.emplace_back("connection", "close");
  } else if (http_minor_ == 0) {
    headers.emplace_back("connection", "keep-alive");
  }

  bool complete = co_await Write(FormatH1ResponseHead("1.1", status, headers));
  std::vector<uint8_t> chunk(kReadChunk);
  while (complete) {
    const std::size_t n = exchange->ReadResponseBody(chunk);
    if (n > 0) {
      if (!has_body) continue;  // Discard; HEAD-style responses.
      std::string out;
      if (chunked) out = std::format("{:x}\r\n", n);
      out.append(reinterpret_cast<const char*>(chunk.data()), n);
      if (chunked) out += "\r\n";
      complete = co_await Write(out);
      continue;
    }
    if (exchange->response_ended) break;
    if (exchange->upstream_failed || write_failed_) {
      // The response is cut short; only closing tells the client.
      complete = false;
      break;
    }
    co_await response_wake_.Wait();
  }
  if (complete && chunked) {
    std::string tail = "0\r\n";
    for (const auto& [name, value] :
         FilterResponseHeaders(exchange->response_trailers)) {
      std::format_to(std::back_inserter(tail), "{}: {}\r\n", name, value);
    }
    tail += "\r\n";
    complete = co_await Write(tail);
  }
  if (!complete) {
    keep_alive_ = false;
    exchange->CancelFromClient();
    transport_->Close();
  }
  exchange->wake_client = nullptr;
  Report(*exchange);
  response_done_ = true;
  reader_wake_.Notify();
}

asio::awaitable<void> H1ServerConnection::Tunnel() {
  auto executor = co_await asio::this_coro::executor;
  auto exchange = std::make_shared<Exchange>();
  exchange->started_ms = SteadyMillis();
  exchange->observed.version = std::format("1.{}", http_minor_);
  exchange->observed.method = method_;
  exchange->observed.target = url_;
  HeaderList lowercase;
  for (const auto& [name, value] : raw_headers_) {
    exchange->observed.header_names.push_back(name);
    lowercase.emplace_back(Lowercase(name), value);
  }
  exchange->observed.headers = lowercase;
  std::string authority(FindHeader(lowercase, "host"));
  if (authority.empty()) authority = client_.server_name;
  exchange->observed.authority = authority;
  exchange->request.method = method_;
  exchange->request.path = url_;
  exchange->request.authority = authority;
  if (hooks_.on_request) hooks_.on_request(*exchange);
  if (exchange->local) {
    keep_alive_ = false;
    co_await WriteResponse(exchange);
    co_return;
  }

  std::unique_ptr<UpstreamTlsTransport> upstream =
      co_await pool_->ConnectHttp1(client_.server_name);
  if (!upstream) {
    exchange->RespondLocally(502, kBadGateway);
    keep_alive_ = false;
    co_await WriteResponse(exchange);
    co_return;
  }
  GlobalMetrics().websocket_tunnels.Inc();

  // Original header names and order; only spoofable fields are replaced.
  std::string head = std::format("{} {} HTTP/1.1\r\n", method_, url_);
  for (const auto& [name, value] : raw_headers_) {
    if (IsSpoofableForwardingHeader(Lowercase(name))) continue;
    std::format_to(std::back_inserter(head), "{}: {}\r\n", name, value);
  }
  HeaderList forwarding;
  AddForwardingHeaders(client_, authority, &forwarding);
  // Headers the owner added in on_request (X-Bot-* verdicts).
  forwarding.insert(forwarding.end(), exchange->request.headers.begin(),
                    exchange->request.headers.end());
  for (const auto& [name, value] : forwarding) {
    std::format_to(std::back_inserter(head), "{}: {}\r\n", name, value);
  }
  head += "\r\n";
  head += buffer_;
  buffer_.clear();
  if (co_await upstream->WriteAll(Bytes(head))) {
    transport_->Close();
    co_return;
  }

  exchange->response.status = 101;
  exchange->response_started = true;
  ScopedWatchdog idle(executor, settings_.idle_timeout, [this, &upstream] {
    transport_->Close();
    upstream->Close();
  });
  const auto on_client_bytes = [](std::size_t) {};
  const auto on_upstream_bytes = [this, &exchange](std::size_t n) {
    exchange->response_bytes += n;
    if (hooks_.on_bytes_to_client) hooks_.on_bytes_to_client(n);
  };
  co_await (Relay(*transport_, *upstream, *idle, on_client_bytes) &&
            Relay(*upstream, *transport_, *idle, on_upstream_bytes));
  exchange->response_ended = true;
  Report(*exchange);
}

asio::awaitable<void> H1ServerConnection::Run() {
  auto self = shared_from_this();
  auto executor = co_await asio::this_coro::executor;
  while (true) {
    headers_complete_ = false;
    message_complete_ = false;
    response_done_ = false;

    // Request head: idle wait for the first byte, then a bounded deadline.
    if (buffer_.empty() && !co_await ReadMore()) break;
    {
      ScopedWatchdog deadline(executor, kHeadTimeout,
                              [this] { transport_->Close(); });
      bool ok = true;
      while (!headers_complete_) {
        if (!Execute()) {
          ok = false;
          break;
        }
        if (headers_complete_) break;
        if (!co_await ReadMore()) {
          ok = false;
          break;
        }
      }
      if (!ok) {
        if (!buffer_.empty() || headers_too_large_) {
          co_await RespondError(headers_too_large_ ? 431 : 400);
        }
        break;
      }
    }

    if (upgrade_) {
      // Let llhttp finish the upgrade request (it has no body).
      Execute();
      co_await Tunnel();
      break;
    }

    std::shared_ptr<Exchange> exchange = exchange_;
    asio::co_spawn(executor, WriteResponse(exchange), asio::detached);

    // Request body, throttled by what the upstream has consumed.
    bool client_ended = false;
    while (!message_complete_ && !response_done_ && !write_failed_) {
      if (exchange->request_body.size() > settings_.max_buffered_body) {
        co_await reader_wake_.Wait();
        continue;
      }
      if (!buffer_.empty()) {
        if (!Execute()) {
          client_ended = true;
          break;
        }
        continue;
      }
      if (!co_await ReadMore()) {
        client_ended = true;
        break;
      }
    }
    if (!message_complete_) {
      // Unread body bytes would be taken for the next request.
      keep_alive_ = false;
      if (client_ended) {
        // Nothing more will reach the client: stop the writer too.
        exchange->CancelFromClient();
        write_failed_ = true;
        transport_->Close();
        response_wake_.Notify();
      }
    }
    while (!response_done_) co_await reader_wake_.Wait();
    if (!keep_alive_ || write_failed_) break;
  }
  transport_->Close();
}

}  // namespace bot_shield
