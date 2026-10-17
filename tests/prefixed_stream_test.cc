#include "net/prefixed_stream.h"

#include <gtest/gtest.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "test_util.h"
#include "tls/cert_store.h"

namespace bot_shield {
namespace {

using asio::ip::tcp;

constexpr auto kUse = asio::as_tuple(asio::use_awaitable);

// Connected loopback socket pair.
std::pair<tcp::socket, tcp::socket> SocketPair(asio::io_context& io) {
  tcp::acceptor acceptor(io,
                         tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
  tcp::socket client(io);
  client.connect(acceptor.local_endpoint());
  tcp::socket server = acceptor.accept();
  return {std::move(client), std::move(server)};
}

TEST(PrefixedStreamTest, YieldsPrefixThenSocketData) {
  asio::io_context io;
  auto [writer, reader] = SocketPair(io);
  asio::write(writer, asio::buffer(std::string("world")));
  writer.shutdown(tcp::socket::shutdown_send);

  const std::string prefix = "hello ";
  PrefixedStream<tcp::socket> stream(
      std::move(reader), std::vector<uint8_t>(prefix.begin(), prefix.end()));
  std::string received;
  asio::co_spawn(
      io,
      [&]() -> asio::awaitable<void> {
        char buffer[4];
        while (true) {
          auto [ec, n] =
              co_await stream.async_read_some(asio::buffer(buffer), kUse);
          received.append(buffer, n);
          if (ec) break;
        }
      },
      asio::detached);
  io.run();
  EXPECT_EQ(received, "hello world");
}

TEST(PrefixedStreamTest, TlsHandshakeOverConsumedClientHello) {
  asio::io_context io;
  auto [client_socket, server_socket] = SocketPair(io);

  const auto certificate = testing::MakeCertificate({"p.test"});
  CertEntry entry;
  std::string error;
  ASSERT_TRUE(BuildCertEntry(certificate.cert_pem, certificate.key_pem, &entry,
                             &error));

  asio::ssl::context client_context(asio::ssl::context::tls_client);
  client_context.set_verify_mode(asio::ssl::verify_none);
  asio::ssl::stream<tcp::socket> client(std::move(client_socket),
                                        client_context);
  SSL_set_tlsext_host_name(client.native_handle(), "p.test");

  std::string server_got;
  std::string client_got;
  asio::co_spawn(
      io,
      [&]() -> asio::awaitable<void> {
        // Consume part of the ClientHello the way the gateway does.
        std::vector<uint8_t> prefix(10);
        auto [read_ec, n] = co_await asio::async_read(
            server_socket, asio::buffer(prefix), kUse);
        EXPECT_FALSE(read_ec);
        asio::ssl::stream<PrefixedStream<tcp::socket>> server(
            PrefixedStream<tcp::socket>(std::move(server_socket),
                                        std::move(prefix)),
            *entry.context);
        auto [handshake_ec] = co_await server.async_handshake(
            asio::ssl::stream_base::server, kUse);
        EXPECT_FALSE(handshake_ec) << handshake_ec.message();
        std::string buffer(4, '\0');
        co_await asio::async_read(server, asio::buffer(buffer), kUse);
        server_got = buffer;
        co_await asio::async_write(server, asio::buffer(std::string("pong")),
                                   kUse);
      },
      asio::detached);
  asio::co_spawn(
      io,
      [&]() -> asio::awaitable<void> {
        auto [ec] = co_await client.async_handshake(
            asio::ssl::stream_base::client, kUse);
        EXPECT_FALSE(ec) << ec.message();
        co_await asio::async_write(client, asio::buffer(std::string("ping")),
                                   kUse);
        std::string buffer(4, '\0');
        co_await asio::async_read(client, asio::buffer(buffer), kUse);
        client_got = buffer;
      },
      asio::detached);
  io.run();
  EXPECT_EQ(server_got, "ping");
  EXPECT_EQ(client_got, "pong");
}

}  // namespace
}  // namespace bot_shield
