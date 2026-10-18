#include "proxy/h2_connection.h"

#include <nghttp2/nghttp2.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "common/log.h"
#include "proxy/transport.h"

namespace bot_shield {
namespace {

constexpr std::size_t kReadBufferSize = std::size_t{16} * 1024;
constexpr std::size_t kWriteBatch = std::size_t{64} * 1024;

}  // namespace

H2Connection::H2Connection(std::unique_ptr<Transport> transport,
                           std::chrono::milliseconds idle_timeout)
    : transport_(std::move(transport)),
      idle_timeout_(idle_timeout),
      last_activity_(std::chrono::steady_clock::now()),
      idle_timer_(transport_->executor()),
      closed_notifier_(transport_->executor()) {}

H2Connection::~H2Connection() {
  if (session_ != nullptr) nghttp2_session_del(session_);
}

std::vector<nghttp2_nv> H2Connection::MakeNva(
    const std::vector<std::pair<std::string, std::string>>& headers) {
  std::vector<nghttp2_nv> nva;
  nva.reserve(headers.size());
  for (const auto& [name, value] : headers) {
    nva.push_back(
        nghttp2_nv{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())),
                   reinterpret_cast<uint8_t*>(const_cast<char*>(value.data())),
                   name.size(), value.size(), NGHTTP2_NV_FLAG_NONE});
  }
  return nva;
}

void H2Connection::StartIo() {
  auto self = shared_from_this();
  auto executor = transport_->executor();
  asio::co_spawn(executor, ReadLoop(), asio::detached);
  asio::co_spawn(executor, IdleLoop(), asio::detached);
  Flush();
}

void H2Connection::Flush() {
  if (writing_ || closed_) return;
  writing_ = true;
  // Never write from inside an nghttp2 callback: post the write pass.
  asio::post(transport_->executor(), [self = shared_from_this()] {
    asio::co_spawn(self->transport_->executor(), self->WriteLoop(),
                   asio::detached);
  });
}

void H2Connection::Close() {
  if (closed_) return;
  closed_ = true;
  transport_->Close();
  idle_timer_.cancel();
  OnClosed();
  closed_notifier_.Notify();
}

asio::awaitable<void> H2Connection::WaitClosed() {
  auto self = shared_from_this();
  while (!closed_) co_await closed_notifier_.Wait();
}

void H2Connection::CloseIfDone() {
  if (!closed_ && nghttp2_session_want_read(session_) == 0 &&
      nghttp2_session_want_write(session_) == 0) {
    Close();
  }
}

asio::awaitable<void> H2Connection::ReadLoop() {
  auto self = shared_from_this();
  std::vector<uint8_t> buffer(kReadBufferSize);
  while (!closed_) {
    auto [ec, n] = co_await transport_->ReadSome(buffer);
    if (ec || closed_) break;
    last_activity_ = std::chrono::steady_clock::now();
    const std::span<const uint8_t> data(buffer.data(), n);
    OnBytesRead(data);
    const nghttp2_ssize consumed =
        nghttp2_session_mem_recv2(session_, data.data(), data.size());
    if (consumed < 0) {
      log::Debug("h2: protocol error: {}",
                 nghttp2_strerror(static_cast<int>(consumed)));
      // Let nghttp2 send its GOAWAY before closing.
      Flush();
      break;
    }
    Flush();
    CloseIfDone();
  }
  // Pending writes (e.g. a GOAWAY) finish first; the write loop closes then.
  read_done_ = true;
  if (!writing_) Close();
}

asio::awaitable<void> H2Connection::WriteLoop() {
  auto self = shared_from_this();
  std::vector<uint8_t> batch;
  while (!closed_) {
    batch.clear();
    while (batch.size() < kWriteBatch) {
      const uint8_t* data = nullptr;
      const nghttp2_ssize n = nghttp2_session_mem_send2(session_, &data);
      if (n < 0) {
        Close();
        co_return;
      }
      if (n == 0) break;
      batch.insert(batch.end(), data, data + n);
    }
    if (batch.empty()) break;
    const std::error_code ec = co_await transport_->WriteAll(batch);
    if (ec) {
      Close();
      co_return;
    }
    last_activity_ = std::chrono::steady_clock::now();
    OnBytesWritten(batch.size());
  }
  writing_ = false;
  if (read_done_) {
    Close();
  } else if (!closed_) {
    CloseIfDone();
  }
}

asio::awaitable<void> H2Connection::IdleLoop() {
  auto self = shared_from_this();
  while (!closed_) {
    idle_timer_.expires_after(idle_timeout_);
    co_await idle_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
    if (closed_) break;
    const auto idle = std::chrono::steady_clock::now() - last_activity_;
    if (idle >= idle_timeout_ && !HasOpenStreams()) {
      // Polite shutdown: GOAWAY, then close once it is written.
      nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
      Flush();
      co_return;
    }
  }
}

}  // namespace bot_shield
