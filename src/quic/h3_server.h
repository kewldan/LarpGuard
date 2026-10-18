#ifndef BOT_SHIELD_QUIC_H3_SERVER_H_
#define BOT_SHIELD_QUIC_H3_SERVER_H_

#include <openssl/base.h>

#include <array>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace bot_shield {

struct GatewayContext;
class QuicConnection;

struct QuicSettings {
  std::chrono::milliseconds idle_timeout{30000};
  // Validate client addresses with a Retry before keeping any state (one
  // extra round trip; spoofed floods then cost nothing).
  bool retry = true;
  // Connections per worker; new ones beyond it are dropped.
  std::size_t max_connections = 10000;
  uint64_t max_streams_bidi = 100;
};

// HTTP/3 listener on the HTTPS port (UDP), one per worker (ADR-011): QUIC
// with ngtcp2 (BoringSSL crypto), HTTP/3 with nghttp3. Requests become
// Exchanges and go to Traefik over the same HTTP/2 pool as TCP traffic,
// with the same verdicts. A client whose SNI has no certificate here gets a
// failed handshake and falls back to TCP (passthrough keeps working).
class QuicServer {
 public:
  QuicServer(asio::io_context& io_context, const GatewayContext& context,
             QuicSettings settings);
  ~QuicServer();
  QuicServer(const QuicServer&) = delete;
  QuicServer& operator=(const QuicServer&) = delete;

  bool Listen(const asio::ip::udp::endpoint& endpoint, bool reuse_port,
              std::string* error);
  void Start();
  // Closes the socket and every connection (CONNECTION_CLOSE, no drain).
  void Stop();

  std::size_t connection_count() const { return connections_.size(); }

  // --- For QuicConnection ---------------------------------------------------
  void Send(const asio::ip::udp::endpoint& remote,
            std::span<const uint8_t> packet);
  void Register(std::string_view cid,
                const std::shared_ptr<QuicConnection>& connection);
  void Unregister(std::string_view cid);
  void Remove(QuicConnection* connection);
  const GatewayContext& context() const { return context_; }
  const QuicSettings& settings() const { return settings_; }
  SSL_CTX* ssl_context() const { return ssl_context_; }
  std::span<const uint8_t> secret() const { return secret_; }
  asio::io_context& io_context() { return io_context_; }

 private:
  asio::awaitable<void> ReceiveLoop();
  void OnDatagram(std::span<const uint8_t> data,
                  const asio::ip::udp::endpoint& remote);
  void SendVersionNegotiation(std::span<const uint8_t> dcid,
                              std::span<const uint8_t> scid,
                              const asio::ip::udp::endpoint& remote);
  void SendRetry(const void* header, const asio::ip::udp::endpoint& remote);

  asio::io_context& io_context_;
  const GatewayContext& context_;
  const QuicSettings settings_;
  asio::ip::udp::socket socket_;
  asio::ip::udp::endpoint local_;
  SSL_CTX* ssl_context_ = nullptr;
  std::array<uint8_t, 32> secret_{};
  // Connection IDs (raw bytes) -> connection; several per connection.
  std::unordered_map<std::string, std::shared_ptr<QuicConnection>> by_cid_;
  std::unordered_map<QuicConnection*, std::shared_ptr<QuicConnection>>
      connections_;
  bool stopped_ = false;
  // Expires with the server; deferred work checks it.
  std::shared_ptr<int> alive_ = std::make_shared<int>(0);
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_QUIC_H3_SERVER_H_
