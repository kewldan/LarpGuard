#ifndef BOT_SHIELD_PROXY_H1_SERVER_H_
#define BOT_SHIELD_PROXY_H1_SERVER_H_

#include <llhttp.h>

#include <asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "proxy/exchange.h"
#include "proxy/http_message.h"
#include "proxy/notifier.h"
#include "proxy/proxy_hooks.h"
#include "proxy/transport.h"

namespace bot_shield {

class UpstreamPool;

// Client-facing HTTP/1.x server connection. Requests are handled one at a
// time (pipelined requests wait in the buffer); each becomes an Exchange sent
// to the upstream pool over HTTP/2. The request body streams up while the
// response streams down. Upgrades (WebSocket) are tunnelled to Traefik over a
// dedicated HTTP/1.1 connection.
class H1ServerConnection
    : public std::enable_shared_from_this<H1ServerConnection> {
 public:
  static std::shared_ptr<H1ServerConnection> Create(
      std::unique_ptr<Transport> transport, UpstreamPool* pool,
      ClientInfo client, ProxyHooks hooks, const ProxySettings& settings);

  H1ServerConnection(const H1ServerConnection&) = delete;
  H1ServerConnection& operator=(const H1ServerConnection&) = delete;

  // Serves requests until the connection ends.
  asio::awaitable<void> Run();
  void DetachHooks() { hooks_ = ProxyHooks{}; }

 private:
  H1ServerConnection(std::unique_ptr<Transport> transport, UpstreamPool* pool,
                     ClientInfo client, ProxyHooks hooks,
                     const ProxySettings& settings);

  // Feeds buffered bytes to llhttp; false on a parse error.
  bool Execute();
  // Reads more client bytes into the buffer; false on EOF, error or timeout.
  asio::awaitable<bool> ReadMore();
  asio::awaitable<bool> Write(std::string_view data);
  void StartExchange();
  asio::awaitable<void> WriteResponse(std::shared_ptr<Exchange> exchange);
  asio::awaitable<void> RespondError(int status);
  asio::awaitable<void> Tunnel();
  void Report(const Exchange& exchange) const;

  static H1ServerConnection& Self(llhttp_t* parser);
  static int OnMessageBegin(llhttp_t* parser);
  static int OnMethod(llhttp_t* parser, const char* at, std::size_t size);
  static int OnUrl(llhttp_t* parser, const char* at, std::size_t size);
  static int OnHeaderField(llhttp_t* parser, const char* at, std::size_t size);
  static int OnHeaderValue(llhttp_t* parser, const char* at, std::size_t size);
  static int OnHeaderValueComplete(llhttp_t* parser);
  static int OnHeadersComplete(llhttp_t* parser);
  static int OnBody(llhttp_t* parser, const char* at, std::size_t size);
  static int OnMessageComplete(llhttp_t* parser);

  std::unique_ptr<Transport> transport_;
  UpstreamPool* pool_;
  ClientInfo client_;
  ProxyHooks hooks_;
  ProxySettings settings_;

  llhttp_settings_t parser_settings_{};
  llhttp_t parser_{};
  std::string buffer_;  // Received, not yet parsed.

  // Current request.
  std::string method_;
  std::string url_;
  std::string field_;
  std::string value_;
  std::vector<std::pair<std::string, std::string>> raw_headers_;
  std::size_t header_bytes_ = 0;
  int http_minor_ = 1;
  bool headers_complete_ = false;
  bool message_complete_ = false;
  bool upgrade_ = false;
  bool keep_alive_ = true;
  bool expect_continue_ = false;
  bool headers_too_large_ = false;
  std::shared_ptr<Exchange> exchange_;

  Notifier reader_wake_;
  Notifier response_wake_;
  bool response_done_ = false;
  bool write_failed_ = false;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_PROXY_H1_SERVER_H_
