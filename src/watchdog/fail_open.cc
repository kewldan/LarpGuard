#include "watchdog/fail_open.h"

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include "config/config.h"

namespace bot_shield {

FailOpenSwitch::Change FailOpenSwitch::Observe(bool healthy) {
  if (healthy) {
    failures_ = 0;
    ++successes_;
    if (open_ != false && successes_ >= recover_after_) return Change::kClose;
  } else {
    successes_ = 0;
    ++failures_;
    if (open_ != true && failures_ >= fail_after_) return Change::kOpen;
  }
  return Change::kNone;
}

void FailOpenSwitch::Applied(Change change) {
  if (change == Change::kOpen) open_ = true;
  if (change == Change::kClose) open_ = false;
}

bool ProbeHealth(const Endpoint& endpoint, std::chrono::milliseconds timeout,
                 std::string* detail) {
  asio::io_context io_context;
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::socket socket(io_context);
  const std::string request = std::format(
      "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
      endpoint.host);
  std::string response;
  // Set by the last handler that runs; unset means the check timed out
  // (`response` then holds the read buffer, not an answer).
  std::optional<std::error_code> result;

  resolver.async_resolve(
      endpoint.host, std::to_string(endpoint.port),
      [&](const std::error_code& ec,
          const asio::ip::tcp::resolver::results_type& results) {
        if (ec) {
          result = ec;
          return;
        }
        asio::async_connect(
            socket, results,
            [&](const std::error_code& connect_ec,
                const asio::ip::tcp::endpoint& /*peer*/) {
              if (connect_ec) {
                result = connect_ec;
                return;
              }
              asio::async_write(
                  socket, asio::buffer(request),
                  [&](const std::error_code& write_ec, std::size_t) {
                    if (write_ec) {
                      result = write_ec;
                      return;
                    }
                    asio::async_read(
                        socket,
                        asio::dynamic_buffer(response, std::size_t{4096}),
                        [&](const std::error_code& read_ec, std::size_t) {
                          result = read_ec == asio::error::eof
                                       ? std::error_code()
                                       : read_ec;
                        });
                  });
            });
      });
  io_context.run_for(timeout);
  if (!result) {
    *detail = std::format("no answer within {} ms", timeout.count());
    return false;
  }
  if (*result) {
    *detail = result->message();
    return false;
  }
  const std::string_view status_line =
      std::string_view(response).substr(0, response.find("\r\n"));
  *detail = std::string(status_line);
  return status_line.starts_with("HTTP/1.1 200 ") ||
         status_line.starts_with("HTTP/1.0 200 ");
}

}  // namespace bot_shield
