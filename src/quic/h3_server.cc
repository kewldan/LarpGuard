#include "quic/h3_server.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <format>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "common/metrics.h"
#include "net/socket_options.h"
#include "proxy/body_rate.h"
#include "proxy/exchange.h"
#include "proxy/http_message.h"
#include "proxy/proxy_hooks.h"
#include "proxy/upstream_pool.h"
#include "server/connection.h"
#include "tls/cert_store.h"
#include "tls/client_hello.h"

namespace bot_shield {
namespace {

constexpr std::size_t kCidLength = 18;
constexpr std::size_t kMaxPacket = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;
constexpr std::size_t kReadChunk = std::size_t{16} * 1024;
constexpr uint64_t kStreamWindow = uint64_t{256} * 1024;
constexpr uint64_t kConnectionWindow = uint64_t{1024} * 1024;
constexpr std::string_view kBadGateway = "bad gateway\n";
constexpr std::chrono::seconds kBodyRateTick{1};

ngtcp2_tstamp Now() {
  return static_cast<ngtcp2_tstamp>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

std::string CidKey(const uint8_t* data, std::size_t length) {
  return {reinterpret_cast<const char*>(data), length};
}

std::string CidKey(const ngtcp2_cid& cid) {
  return CidKey(cid.data, cid.datalen);
}

void RandomBytes(uint8_t* out, std::size_t length) { RAND_bytes(out, length); }

std::string ToString(nghttp3_rcbuf* buffer) {
  const nghttp3_vec vec = nghttp3_rcbuf_get_buf(buffer);
  return {reinterpret_cast<const char*>(vec.base), vec.len};
}

std::vector<nghttp3_nv> MakeNva(const HeaderList& headers) {
  std::vector<nghttp3_nv> nva;
  nva.reserve(headers.size());
  for (const auto& [name, value] : headers) {
    nva.push_back({reinterpret_cast<const uint8_t*>(name.data()),
                   reinterpret_cast<const uint8_t*>(value.data()), name.size(),
                   value.size(), NGHTTP3_NV_FLAG_NONE});
  }
  return nva;
}

// Transport parameter ids in ClientHello order (GREASE left out), e.g.
// "1,3,4,5,6,7,8,9,f": the QUIC stack's fingerprint.
std::string TransportParamsFingerprint(const SSL_CLIENT_HELLO* hello) {
  const uint8_t* data = nullptr;
  std::size_t length = 0;
  if (SSL_early_callback_ctx_extension_get(hello, 0x39, &data, &length) == 0) {
    return {};
  }
  const auto varint = [&](uint64_t* value) {
    if (length == 0) return false;
    const std::size_t size = std::size_t{1} << (data[0] >> 6);
    if (length < size) return false;
    *value = data[0] & 0x3f;
    for (std::size_t i = 1; i < size; ++i) *value = (*value << 8) | data[i];
    data += size;
    length -= size;
    return true;
  };
  std::string out;
  uint64_t id = 0;
  uint64_t size = 0;
  while (varint(&id) && varint(&size) && size <= length) {
    data += size;
    length -= size;
    if (id >= 27 && (id - 27) % 31 == 0) continue;  // GREASE.
    if (!out.empty()) out.push_back(',');
    out += std::format("{:x}", id);
  }
  return out;
}

}  // namespace

// One QUIC connection with its HTTP/3 session.
class QuicConnection : public std::enable_shared_from_this<QuicConnection> {
 public:
  QuicConnection(QuicServer* server, asio::ip::udp::endpoint remote,
                 asio::ip::udp::endpoint local)
      : server_(server),
        remote_(std::move(remote)),
        local_(std::move(local)),
        timer_(server->io_context()),
        body_timer_(server->io_context()) {
    conn_ref_.get_conn = [](ngtcp2_crypto_conn_ref* ref) {
      return static_cast<QuicConnection*>(ref->user_data)->conn_;
    };
    conn_ref_.user_data = this;
  }

  ~QuicConnection() {
    if (h3_ != nullptr) nghttp3_conn_del(h3_);
    if (conn_ != nullptr) ngtcp2_conn_del(conn_);
    if (ssl_ != nullptr) SSL_free(ssl_);
  }

  QuicConnection(const QuicConnection&) = delete;
  QuicConnection& operator=(const QuicConnection&) = delete;

  bool Init(const ngtcp2_pkt_hd& header, const ngtcp2_cid* original_dcid) {
    ngtcp2_cid scid;
    scid.datalen = kCidLength;
    RandomBytes(scid.data, scid.datalen);

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = Now();
    settings.max_window = 6 * kConnectionWindow;
    settings.max_stream_window = 6 * kStreamWindow;
    if (original_dcid != nullptr) {
      settings.token = header.token;
      settings.tokenlen = header.tokenlen;
    }

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    const QuicSettings& quic = server_->settings();
    params.initial_max_stream_data_bidi_remote = kStreamWindow;
    params.initial_max_stream_data_uni = kStreamWindow;
    params.initial_max_data = kConnectionWindow;
    params.initial_max_streams_bidi = quic.max_streams_bidi;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = static_cast<ngtcp2_duration>(
        quic.idle_timeout.count() * NGTCP2_MILLISECONDS);
    params.active_connection_id_limit = 4;
    // One worker per 4-tuple (SO_REUSEPORT): a migrated client would land
    // on another worker that does not know it.
    params.disable_active_migration = 1;
    params.stateless_reset_token_present = 1;
    ngtcp2_crypto_generate_stateless_reset_token(
        params.stateless_reset_token, server_->secret().data(),
        server_->secret().size(), &scid);
    if (original_dcid != nullptr) {
      params.original_dcid = *original_dcid;
      params.retry_scid = header.dcid;
      params.retry_scid_present = 1;
    } else {
      params.original_dcid = header.dcid;
    }
    params.original_dcid_present = 1;

    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx =
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data2 =
        ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.rand = [](uint8_t* dest, std::size_t length,
                        const ngtcp2_rand_ctx*) { RandomBytes(dest, length); };
    callbacks.get_new_connection_id2 = &OnNewConnectionId;
    callbacks.remove_connection_id = &OnRemoveConnectionId;
    callbacks.handshake_completed = &OnHandshakeCompleted;
    callbacks.recv_stream_data = &OnRecvStreamData;
    callbacks.acked_stream_data_offset = &OnAckedStreamData;
    callbacks.stream_close = &OnStreamClose;
    callbacks.stream_reset = &OnStreamReset;
    callbacks.stream_stop_sending = &OnStreamStopSending;
    callbacks.extend_max_remote_streams_bidi = &OnExtendMaxRemoteStreams;
    callbacks.extend_max_stream_data = &OnExtendMaxStreamData;

    ngtcp2_path path = Path();
    if (ngtcp2_conn_server_new(&conn_, &header.scid, &scid, &path,
                               header.version, &callbacks, &settings, &params,
                               nullptr, this) != 0) {
      return false;
    }
    ssl_ = SSL_new(server_->ssl_context());
    if (ssl_ == nullptr) return false;
    SSL_set_app_data(ssl_, &conn_ref_);
    SSL_set_accept_state(ssl_);
    ngtcp2_conn_set_tls_native_handle(conn_, ssl_);
    server_->Register(CidKey(scid), shared_from_this());
    scids_.push_back(CidKey(scid));
    return true;
  }

  // From the SSL select-certificate callback.
  static QuicConnection* FromSsl(const SSL* ssl) {
    auto* ref = static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl));
    return ref == nullptr ? nullptr
                          : static_cast<QuicConnection*>(ref->user_data);
  }

  // The ClientHello arrived: pick the certificate, start the observer.
  bool OnClientHello(const SSL_CLIENT_HELLO* client_hello) {
    // Rebuild the TLS record our parser (and JA4) expect.
    const std::size_t body = client_hello->client_hello_len;
    std::vector<uint8_t> record = {0x16,
                                   0x03,
                                   0x01,
                                   static_cast<uint8_t>((body + 4) >> 8),
                                   static_cast<uint8_t>(body + 4),
                                   0x01,
                                   static_cast<uint8_t>(body >> 16),
                                   static_cast<uint8_t>(body >> 8),
                                   static_cast<uint8_t>(body)};
    record.insert(record.end(), client_hello->client_hello,
                  client_hello->client_hello + body);
    ClientHello hello;
    if (ParseClientHello(record, &hello) != ParseStatus::kOk ||
        hello.server_name.empty()) {
      GlobalMetrics().quic_rejected.Inc();
      return false;
    }
    const GatewayContext& context = server_->context();
    const auto certificate =
        context.certificates->snapshot()->Find(hello.server_name);
    const bool passthrough =
        context.classifier->IsPassthroughHost(hello.server_name) ||
        (context.labels != nullptr &&
         context.labels->snapshot()->IsPassthrough(hello.server_name));
    if (certificate == nullptr || passthrough) {
      // No certificate (or not ours to terminate): the client falls back to
      // TCP, where passthrough applies.
      GlobalMetrics().quic_rejected.Inc();
      return false;
    }
    SSL_CTX* source = certificate->context->native_handle();
    STACK_OF(X509)* chain = nullptr;
    SSL_CTX_get0_chain_certs(source, &chain);
    if (SSL_use_certificate(ssl_, SSL_CTX_get0_certificate(source)) != 1 ||
        SSL_use_PrivateKey(ssl_, SSL_CTX_get0_privatekey(source)) != 1 ||
        (chain != nullptr && SSL_set1_chain(ssl_, chain) != 1)) {
      return false;
    }
    client_.address = remote_.address();
    client_.local_port = local_.port();
    client_.server_name = hello.server_name;
    observer_ = MakeQuicObserver(context, remote_, local_, hello,
                                 TransportParamsFingerprint(client_hello),
                                 server_->io_context().get_executor());
    hooks_ = observer_->Hooks();
    return true;
  }

  void OnDatagram(std::span<const uint8_t> data,
                  const asio::ip::udp::endpoint& remote) {
    if (closed_) return;
    if (hooks_.on_client_bytes) hooks_.on_client_bytes(data);
    remote_ = remote;
    ngtcp2_path path = Path();
    ngtcp2_pkt_info info{};
    int rv = 0;
    {
      const CallbackScope scope(this);
      rv = ngtcp2_conn_read_pkt(conn_, &path, &info, data.data(), data.size(),
                                Now());
    }
    if (rv != 0) {
      if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_DROP_CONN) {
        Close(nullptr);
      } else {
        ngtcp2_ccerr error;
        ngtcp2_ccerr_default(&error);
        if (rv == NGTCP2_ERR_CRYPTO) {
          ngtcp2_ccerr_set_tls_alert(&error, ngtcp2_conn_get_tls_alert(conn_),
                                     nullptr, 0);
        } else {
          ngtcp2_ccerr_set_liberr(&error, rv, nullptr, 0);
        }
        Close(&error);
      }
      return;
    }
    Flush();
  }

  // Sends what is pending and rearms the timer. Inside ngtcp2/nghttp3
  // calls (a callback answering locally, waking a stream, ...) the write is
  // deferred to the next turn of the loop: they must not be re-entered.
  void Flush() {
    if (closed_) return;
    if (callback_depth_ > 0) {
      if (!flush_posted_) {
        flush_posted_ = true;
        asio::post(server_->io_context(), [weak = weak_from_this()] {
          if (auto self = weak.lock()) {
            self->flush_posted_ = false;
            self->Flush();
          }
        });
      }
      return;
    }
    bool written = false;
    {
      const CallbackScope scope(this);
      written = WritePackets();
    }
    if (!written) return;
    ArmTimer();
  }

  // Marks a call into ngtcp2/nghttp3 (their callbacks may run inside it).
  class CallbackScope {
   public:
    explicit CallbackScope(QuicConnection* connection)
        : connection_(connection) {
      ++connection_->callback_depth_;
    }
    ~CallbackScope() { --connection_->callback_depth_; }
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;

   private:
    QuicConnection* connection_;
  };

  // CONNECTION_CLOSE (when `error` is set), then forget the connection.
  void Close(const ngtcp2_ccerr* error) {
    if (closed_) return;
    closed_ = true;
    if (error != nullptr && conn_ != nullptr &&
        !ngtcp2_conn_in_closing_period(conn_) &&
        !ngtcp2_conn_in_draining_period(conn_)) {
      std::array<uint8_t, kMaxPacket> buffer{};
      ngtcp2_path_storage storage;
      ngtcp2_path_storage_zero(&storage);
      ngtcp2_pkt_info info{};
      const ngtcp2_ssize n = ngtcp2_conn_write_connection_close(
          conn_, &storage.path, &info, buffer.data(), buffer.size(), error,
          Now());
      if (n > 0) {
        server_->Send(remote_,
                      std::span(buffer.data(), static_cast<std::size_t>(n)));
      }
    }
    timer_.cancel();
    body_timer_.cancel();
    for (auto& [id, stream] : streams_) FinishStream(*stream, true);
    streams_.clear();
    for (const std::string& cid : scids_) server_->Unregister(cid);
    scids_.clear();
    observer_.reset();
    server_->Remove(this);
  }

 private:
  struct Stream {
    int64_t id = 0;
    ProxyRequest request;
    HttpRequest observed;
    HeaderList trailers;
    std::shared_ptr<Exchange> exchange;
    // Minimum body rate while the request body is still arriving.
    BodyRate body_rate;
    bool response_submitted = false;
    bool reported = false;
    // Response bytes handed to nghttp3, kept until acknowledged.
    std::deque<std::string> unacked;
    std::size_t acked_in_front = 0;
  };

  ngtcp2_path Path() {
    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(local_.data());
    path.local.addrlen = static_cast<ngtcp2_socklen>(local_.size());
    path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(remote_.data());
    path.remote.addrlen = static_cast<ngtcp2_socklen>(remote_.size());
    return path;
  }

  bool WritePackets() {
    // packet_ is a member: after NGTCP2_ERR_WRITE_MORE ngtcp2 finishes the
    // packet in the same buffer on the next call, possibly in a later
    // WritePackets (a stack buffer would be gone by then).
    std::array<uint8_t, kMaxPacket>& buffer = packet_;
    ngtcp2_path_storage storage;
    ngtcp2_path_storage_zero(&storage);
    ngtcp2_pkt_info info{};
    const ngtcp2_tstamp now = Now();
    // Up to 64 packets per turn; calls that only add stream data to the
    // packet being built (WRITE_MORE, blocked streams) do not count, but
    // are bounded too.
    int packets = 0;
    for (int calls = 0; packets < 64 && calls < 4096; ++calls) {
      int64_t stream_id = -1;
      int fin = 0;
      std::array<nghttp3_vec, 16> vec{};
      nghttp3_ssize count = 0;
      if (h3_ != nullptr && ngtcp2_conn_get_max_data_left(conn_) > 0) {
        count = nghttp3_conn_writev_stream(h3_, &stream_id, &fin, vec.data(),
                                           vec.size());
        if (count < 0) {
          CloseWithApplicationError(
              nghttp3_err_infer_quic_app_error_code(static_cast<int>(count)));
          return false;
        }
      }
      ngtcp2_ssize written_data = -1;
      uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
      if (fin != 0) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      const ngtcp2_ssize n = ngtcp2_conn_writev_stream(
          conn_, &storage.path, &info, buffer.data(), buffer.size(),
          &written_data, flags, stream_id,
          reinterpret_cast<const ngtcp2_vec*>(vec.data()),
          static_cast<std::size_t>(count), now);
      if (n < 0) {
        switch (n) {
          case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            nghttp3_conn_block_stream(h3_, stream_id);
            continue;
          case NGTCP2_ERR_STREAM_SHUT_WR:
            nghttp3_conn_shutdown_stream_write(h3_, stream_id);
            continue;
          case NGTCP2_ERR_WRITE_MORE:
            nghttp3_conn_add_write_offset(
                h3_, stream_id, static_cast<std::size_t>(written_data));
            continue;
          default: {
            ngtcp2_ccerr error;
            ngtcp2_ccerr_default(&error);
            ngtcp2_ccerr_set_liberr(&error, static_cast<int>(n), nullptr, 0);
            Close(&error);
            return false;
          }
        }
      }
      if (written_data >= 0 && h3_ != nullptr) {
        nghttp3_conn_add_write_offset(h3_, stream_id,
                                      static_cast<std::size_t>(written_data));
      }
      if (n == 0) return true;
      if (hooks_.on_bytes_to_client) {
        hooks_.on_bytes_to_client(static_cast<std::size_t>(n));
      }
      server_->Send(remote_,
                    std::span(buffer.data(), static_cast<std::size_t>(n)));
      ++packets;
    }
    // More to send: continue on the next turn of the loop.
    asio::post(server_->io_context(), [weak = weak_from_this()] {
      if (auto self = weak.lock()) self->Flush();
    });
    return true;
  }

  void ArmTimer() {
    const ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn_);
    const ngtcp2_tstamp now = Now();
    const auto delay = std::chrono::nanoseconds(
        expiry > now ? std::min<ngtcp2_tstamp>(
                           expiry - now, ngtcp2_tstamp{3600} * NGTCP2_SECONDS)
                     : 0);
    timer_.expires_after(delay);
    timer_.async_wait([weak = weak_from_this()](const std::error_code& ec) {
      if (ec) return;
      auto self = weak.lock();
      if (!self || self->closed_) return;
      int rv = 0;
      {
        const CallbackScope scope(self.get());
        rv = ngtcp2_conn_handle_expiry(self->conn_, Now());
      }
      if (rv != 0) {
        // Idle timeout or handshake timeout: nothing to say to the peer.
        self->Close(nullptr);
        return;
      }
      self->Flush();
    });
  }

  // Charges streams waiting for request body bytes once a second and
  // resets those below the minimum rate (BodyRate).
  void ArmBodyTimer() {
    if (body_timer_armed_ || closed_) return;
    body_timer_armed_ = true;
    body_tick_ = std::chrono::steady_clock::now();
    body_timer_.expires_after(kBodyRateTick);
    body_timer_.async_wait(
        [weak = weak_from_this()](const std::error_code& ec) {
          auto self = weak.lock();
          if (!self) return;
          self->body_timer_armed_ = false;
          if (ec || self->closed_) return;
          self->CheckBodyRates();
        });
  }

  void CheckBodyRates() {
    const auto waited = std::chrono::steady_clock::now() - body_tick_;
    bool pending = false;
    {
      const CallbackScope scope(this);
      for (auto& [id, stream] : streams_) {
        if (!stream->body_rate.enabled() || !stream->exchange) continue;
        const Exchange& exchange = *stream->exchange;
        if (exchange.request_ended) {
          stream->body_rate = BodyRate();
          continue;
        }
        pending = true;
        // Bytes the upstream has not taken yet: not the client's delay.
        if (!exchange.request_body.empty()) continue;
        if (stream->body_rate.Charge(waited)) {
          GlobalMetrics().request_body_timeouts.Inc();
          stream->body_rate = BodyRate();
          ngtcp2_conn_shutdown_stream(conn_, 0, id,
                                      NGHTTP3_H3_REQUEST_CANCELLED);
        }
      }
    }
    Flush();
    if (pending) ArmBodyTimer();
  }

  void CloseWithApplicationError(uint64_t code) {
    ngtcp2_ccerr error;
    ngtcp2_ccerr_default(&error);
    ngtcp2_ccerr_set_application_error(&error, code, nullptr, 0);
    Close(&error);
  }

  // Idempotent: called when the handshake completes, or earlier by the first
  // stream data (a client's 1-RTT request can arrive before its Finished).
  bool SetupHttp3() {
    if (h3_ != nullptr) return true;
    nghttp3_callbacks callbacks{};
    callbacks.acked_stream_data = &H3AckedStreamData;
    callbacks.stream_close = &H3StreamClose;
    callbacks.recv_data = &H3RecvData;
    callbacks.deferred_consume = &H3DeferredConsume;
    callbacks.begin_headers = &H3BeginHeaders;
    callbacks.recv_header = &H3RecvHeader;
    callbacks.end_headers = &H3EndHeaders;
    callbacks.recv_trailer = &H3RecvTrailer;
    callbacks.end_stream = &H3EndStream;
    callbacks.stop_sending = &H3StopSending;
    callbacks.reset_stream = &H3ResetStream;
    callbacks.rand = &RandomBytes;
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    // No QPACK dynamic table for requests: each header block decodes on its
    // own. With one, a request can wait for the client's encoder stream, and
    // some clients never send it (curl 8.14 with OpenSSL QUIC writes its
    // control and QPACK streams before the handshake, they get blocked and
    // are never retried; its requests then hang until the idle timeout).
    settings.qpack_max_dtable_capacity = 0;
    settings.qpack_blocked_streams = 0;
    settings.max_field_section_size = uint64_t{64} * 1024;
    if (nghttp3_conn_server_new(&h3_, &callbacks, &settings, nullptr, this) !=
        0) {
      return false;
    }
    // What we allowed the client (transport parameter), raised later by
    // extend_max_remote_streams_bidi.
    nghttp3_conn_set_max_client_streams_bidi(
        h3_, server_->settings().max_streams_bidi);
    int64_t control = 0;
    int64_t encoder = 0;
    int64_t decoder = 0;
    return ngtcp2_conn_open_uni_stream(conn_, &control, nullptr) == 0 &&
           nghttp3_conn_bind_control_stream(h3_, control) == 0 &&
           ngtcp2_conn_open_uni_stream(conn_, &encoder, nullptr) == 0 &&
           ngtcp2_conn_open_uni_stream(conn_, &decoder, nullptr) == 0 &&
           nghttp3_conn_bind_qpack_streams(h3_, encoder, decoder) == 0;
  }

  Stream* FindStream(int64_t id) {
    const auto it = streams_.find(id);
    return it == streams_.end() ? nullptr : it->second.get();
  }

  void ExtendWindow(int64_t stream_id, std::size_t size) {
    if (closed_ || size == 0) return;
    ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, size);
    ngtcp2_conn_extend_max_offset(conn_, size);
  }

  void OnRequestHeaders(Stream& stream, bool end_stream) {
    auto exchange = std::make_shared<Exchange>();
    exchange->started_ms = SteadyMillis();
    exchange->request = std::move(stream.request);
    exchange->request.headers = FilterRequestHeaders(exchange->request.headers);
    AddForwardingHeaders(client_, exchange->request.authority,
                         &exchange->request.headers);
    exchange->observed = std::move(stream.observed);
    exchange->request_ended = end_stream;
    if (!end_stream && !BodyRateExempt(FindHeader(exchange->request.headers,
                                                  "content-type"))) {
      const ProxySettings& proxy = server_->context().proxy_settings;
      stream.body_rate =
          BodyRate(proxy.request_body_timeout, proxy.request_body_min_rate);
      if (stream.body_rate.enabled()) ArmBodyTimer();
    }
    const int64_t id = stream.id;
    std::weak_ptr<QuicConnection> weak = weak_from_this();
    exchange->wake_client = [weak, id] {
      if (auto self = weak.lock()) self->OnResponseProgress(id);
    };
    exchange->request_consumed = [weak, id](std::size_t size) {
      auto self = weak.lock();
      if (!self || self->closed_) return;
      self->ExtendWindow(id, size);
      self->Flush();
    };
    stream.exchange = exchange;
    if (exchange->request.method == "CONNECT") {
      exchange->RespondLocally(405, "method not allowed\n");
      return;
    }
    if (hooks_.on_request) hooks_.on_request(*exchange);
    if (!exchange->local) {
      server_->context().pool->Dispatch(client_.server_name, exchange);
    }
  }

  void OnResponseProgress(int64_t id) {
    if (closed_ || h3_ == nullptr) return;
    Stream* stream = FindStream(id);
    if (stream == nullptr || !stream->exchange) return;
    Exchange& exchange = *stream->exchange;
    if (!stream->response_submitted) {
      if (exchange.upstream_failed && !exchange.response_started) {
        exchange.RespondLocally(502, kBadGateway);  // Wakes us again.
        return;
      }
      if (!exchange.response_started) return;
      stream->response_submitted = true;
      HeaderList headers = {
          {":status", std::to_string(exchange.response.status)}};
      for (auto& header : FilterResponseHeaders(exchange.response.headers)) {
        headers.push_back(std::move(header));
      }
      SetAltSvc(server_->context().proxy_settings.alt_svc, &headers);
      const std::vector<nghttp3_nv> nva = MakeNva(headers);
      const bool no_body = exchange.response_ended &&
                           exchange.response_body.empty() &&
                           exchange.response_trailers.empty();
      nghttp3_data_reader reader{&H3ReadData};
      nghttp3_conn_submit_response(h3_, id, nva.data(), nva.size(),
                                   no_body ? nullptr : &reader);
    } else if (exchange.upstream_failed) {
      ngtcp2_conn_shutdown_stream(conn_, 0, id, NGHTTP3_H3_INTERNAL_ERROR);
    } else {
      nghttp3_conn_resume_stream(h3_, id);
    }
    Flush();
  }

  void FinishStream(Stream& stream, bool connection_gone) const {
    if (!stream.exchange) return;
    Exchange& exchange = *stream.exchange;
    if (connection_gone || !exchange.response_ended ||
        !exchange.response_body.empty()) {
      exchange.CancelFromClient();
    }
    exchange.wake_client = nullptr;
    exchange.request_consumed = nullptr;
    if (!stream.reported) {
      stream.reported = true;
      if (exchange.local) {
        GlobalMetrics().local_responses.Inc();
      } else {
        GlobalMetrics().proxied_requests.Inc();
      }
      if (hooks_.on_done) hooks_.on_done(exchange);
    }
  }

  // --- ngtcp2 callbacks ------------------------------------------------------

  static QuicConnection* Self(void* user_data) {
    return static_cast<QuicConnection*>(user_data);
  }

  static int OnNewConnectionId(ngtcp2_conn* /*conn*/, ngtcp2_cid* cid,
                               ngtcp2_stateless_reset_token* token,
                               std::size_t length, void* user_data) {
    QuicConnection* self = Self(user_data);
    cid->datalen = length;
    RandomBytes(cid->data, length);
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token->data, self->server_->secret().data(),
            self->server_->secret().size(), cid) != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    self->server_->Register(CidKey(*cid), self->shared_from_this());
    self->scids_.push_back(CidKey(*cid));
    return 0;
  }

  static int OnRemoveConnectionId(ngtcp2_conn* /*conn*/, const ngtcp2_cid* cid,
                                  void* user_data) {
    QuicConnection* self = Self(user_data);
    const std::string key = CidKey(*cid);
    self->server_->Unregister(key);
    std::erase(self->scids_, key);
    return 0;
  }

  static int OnHandshakeCompleted(ngtcp2_conn* /*conn*/, void* user_data) {
    GlobalMetrics().quic_handshakes.Inc();
    return Self(user_data)->SetupHttp3() ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
  }

  static int OnRecvStreamData(ngtcp2_conn* conn, uint32_t flags,
                              int64_t stream_id, uint64_t /*offset*/,
                              const uint8_t* data, std::size_t length,
                              void* user_data, void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    // Dropping the data here would lose the request for good: QUIC counts it
    // as delivered.
    if (!self->SetupHttp3()) return NGTCP2_ERR_CALLBACK_FAILURE;
    const nghttp3_ssize consumed = nghttp3_conn_read_stream2(
        self->h3_, stream_id, data, length,
        (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0 ? 1 : 0, Now());
    if (consumed < 0) {
      // An HTTP/3 protocol error: read_pkt fails and the connection closes.
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id,
                                         static_cast<uint64_t>(consumed));
    ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(consumed));
    return 0;
  }

  static int OnAckedStreamData(ngtcp2_conn* /*conn*/, int64_t stream_id,
                               uint64_t /*offset*/, uint64_t length,
                               void* user_data, void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    if (self->h3_ != nullptr &&
        nghttp3_conn_add_ack_offset(self->h3_, stream_id, length) != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  static int OnStreamClose(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void* user_data,
                           void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    if ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) == 0) {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    if (self->h3_ != nullptr) {
      const int rv =
          nghttp3_conn_close_stream(self->h3_, stream_id, app_error_code);
      if (rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
    }
    if (ngtcp2_is_bidi_stream(stream_id) != 0) {
      ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    }
    return 0;
  }

  static int OnStreamReset(ngtcp2_conn* /*conn*/, int64_t stream_id,
                           uint64_t /*final_size*/, uint64_t /*app_error_code*/,
                           void* user_data, void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    if (self->h3_ != nullptr &&
        nghttp3_conn_shutdown_stream_read(self->h3_, stream_id) != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  static int OnStreamStopSending(ngtcp2_conn* conn, int64_t stream_id,
                                 uint64_t app_error_code, void* user_data,
                                 void* stream_user_data) {
    return OnStreamReset(conn, stream_id, 0, app_error_code, user_data,
                         stream_user_data);
  }

  static int OnExtendMaxRemoteStreams(ngtcp2_conn* /*conn*/,
                                      uint64_t max_streams, void* user_data) {
    QuicConnection* self = Self(user_data);
    if (self->h3_ != nullptr) {
      nghttp3_conn_set_max_client_streams_bidi(self->h3_, max_streams);
    }
    return 0;
  }

  static int OnExtendMaxStreamData(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                   uint64_t /*max_data*/, void* user_data,
                                   void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    if (self->h3_ != nullptr &&
        nghttp3_conn_unblock_stream(self->h3_, stream_id) != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // --- nghttp3 callbacks -----------------------------------------------------

  static int H3AckedStreamData(nghttp3_conn* /*conn*/, int64_t stream_id,
                               uint64_t length, void* user_data,
                               void* /*stream_user_data*/) {
    Stream* stream = Self(user_data)->FindStream(stream_id);
    if (stream == nullptr) return 0;
    auto remaining = static_cast<std::size_t>(length);
    while (remaining > 0 && !stream->unacked.empty()) {
      const std::size_t front =
          stream->unacked.front().size() - stream->acked_in_front;
      if (remaining < front) {
        stream->acked_in_front += remaining;
        break;
      }
      remaining -= front;
      stream->unacked.pop_front();
      stream->acked_in_front = 0;
    }
    return 0;
  }

  static int H3StreamClose(nghttp3_conn* /*conn*/, int64_t stream_id,
                           uint64_t /*app_error_code*/, void* user_data,
                           void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    const auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) return 0;
    self->FinishStream(*it->second, false);
    self->streams_.erase(it);
    return 0;
  }

  static int H3RecvData(nghttp3_conn* /*conn*/, int64_t stream_id,
                        const uint8_t* data, std::size_t length,
                        void* user_data, void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    Stream* stream = self->FindStream(stream_id);
    if (stream == nullptr || !stream->exchange || stream->exchange->local) {
      self->ExtendWindow(stream_id, length);
      return 0;
    }
    // Credit comes back through request_consumed as the upstream reads.
    stream->body_rate.Received(length);
    stream->exchange->PushRequestBody(std::span(data, length));
    return 0;
  }

  static int H3DeferredConsume(nghttp3_conn* /*conn*/, int64_t stream_id,
                               std::size_t consumed, void* user_data,
                               void* /*stream_user_data*/) {
    Self(user_data)->ExtendWindow(stream_id, consumed);
    return 0;
  }

  static int H3BeginHeaders(nghttp3_conn* /*conn*/, int64_t stream_id,
                            void* user_data, void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    auto stream = std::make_unique<Stream>();
    stream->id = stream_id;
    stream->observed.version = "3";
    self->streams_[stream_id] = std::move(stream);
    return 0;
  }

  static int H3RecvHeader(nghttp3_conn* /*conn*/, int64_t stream_id,
                          int32_t /*token*/, nghttp3_rcbuf* name,
                          nghttp3_rcbuf* value, uint8_t /*flags*/,
                          void* user_data, void* /*stream_user_data*/) {
    Stream* stream = Self(user_data)->FindStream(stream_id);
    if (stream == nullptr) return 0;
    std::string header = ToString(name);
    std::string text = ToString(value);
    if (header.starts_with(':')) {
      if (header == ":method") {
        stream->request.method = text;
        stream->observed.method = text;
      } else if (header == ":authority") {
        stream->request.authority = text;
        stream->observed.authority = text;
      } else if (header == ":path") {
        stream->request.path = text;
        stream->observed.target = text;
      }
      stream->observed.pseudo_header_order.push_back(std::move(header));
      return 0;
    }
    stream->observed.header_names.push_back(header);
    stream->observed.headers.emplace_back(header, text);
    stream->request.headers.emplace_back(std::move(header), std::move(text));
    return 0;
  }

  static int H3EndHeaders(nghttp3_conn* /*conn*/, int64_t stream_id, int fin,
                          void* user_data, void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    Stream* stream = self->FindStream(stream_id);
    if (stream == nullptr || stream->exchange) return 0;
    if (stream->request.authority.empty()) {
      stream->request.authority =
          std::string(FindHeader(stream->request.headers, "host"));
    }
    self->OnRequestHeaders(*stream, fin != 0);
    return 0;
  }

  static int H3RecvTrailer(nghttp3_conn* /*conn*/, int64_t stream_id,
                           int32_t /*token*/, nghttp3_rcbuf* name,
                           nghttp3_rcbuf* value, uint8_t /*flags*/,
                           void* user_data, void* /*stream_user_data*/) {
    Stream* stream = Self(user_data)->FindStream(stream_id);
    if (stream != nullptr) {
      stream->trailers.emplace_back(ToString(name), ToString(value));
    }
    return 0;
  }

  static int H3EndStream(nghttp3_conn* /*conn*/, int64_t stream_id,
                         void* user_data, void* /*stream_user_data*/) {
    Stream* stream = Self(user_data)->FindStream(stream_id);
    if (stream != nullptr && stream->exchange &&
        !stream->exchange->request_ended) {
      stream->exchange->EndRequest(std::move(stream->trailers));
    }
    return 0;
  }

  static int H3StopSending(nghttp3_conn* /*conn*/, int64_t stream_id,
                           uint64_t app_error_code, void* user_data,
                           void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    ngtcp2_conn_shutdown_stream_read(self->conn_, 0, stream_id, app_error_code);
    return 0;
  }

  static int H3ResetStream(nghttp3_conn* /*conn*/, int64_t stream_id,
                           uint64_t app_error_code, void* user_data,
                           void* /*stream_user_data*/) {
    QuicConnection* self = Self(user_data);
    ngtcp2_conn_shutdown_stream_write(self->conn_, 0, stream_id,
                                      app_error_code);
    return 0;
  }

  static nghttp3_ssize H3ReadData(nghttp3_conn* conn, int64_t stream_id,
                                  nghttp3_vec* vec, std::size_t /*count*/,
                                  uint32_t* flags, void* user_data,
                                  void* /*stream_user_data*/) {
    Stream* stream = Self(user_data)->FindStream(stream_id);
    if (stream == nullptr || !stream->exchange) {
      *flags |= NGHTTP3_DATA_FLAG_EOF;
      return 0;
    }
    Exchange& exchange = *stream->exchange;
    if (exchange.upstream_failed) return NGHTTP3_ERR_CALLBACK_FAILURE;
    std::string chunk(kReadChunk, '\0');
    const std::size_t n = exchange.ReadResponseBody(
        std::span(reinterpret_cast<uint8_t*>(chunk.data()), chunk.size()));
    if (n == 0) {
      if (!exchange.response_ended) return NGHTTP3_ERR_WOULDBLOCK;
      *flags |= NGHTTP3_DATA_FLAG_EOF;
      if (!exchange.response_trailers.empty()) {
        *flags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
        const HeaderList trailers =
            FilterResponseHeaders(exchange.response_trailers);
        const std::vector<nghttp3_nv> nva = MakeNva(trailers);
        nghttp3_conn_submit_trailers(conn, stream_id, nva.data(), nva.size());
      }
      return 0;
    }
    chunk.resize(n);
    stream->unacked.push_back(std::move(chunk));
    const std::string& kept = stream->unacked.back();
    vec[0].base = reinterpret_cast<uint8_t*>(const_cast<char*>(kept.data()));
    vec[0].len = kept.size();
    if (exchange.response_ended && exchange.response_body.empty() &&
        exchange.response_trailers.empty()) {
      *flags |= NGHTTP3_DATA_FLAG_EOF;
    }
    return 1;
  }

  ngtcp2_crypto_conn_ref conn_ref_{};
  QuicServer* server_;
  asio::ip::udp::endpoint remote_;
  asio::ip::udp::endpoint local_;
  asio::steady_timer timer_;
  asio::steady_timer body_timer_;
  std::chrono::steady_clock::time_point body_tick_;
  bool body_timer_armed_ = false;
  ngtcp2_conn* conn_ = nullptr;
  SSL* ssl_ = nullptr;
  nghttp3_conn* h3_ = nullptr;
  // Packet being written (see WritePackets).
  std::array<uint8_t, kMaxPacket> packet_{};
  ClientInfo client_;
  std::unique_ptr<QuicObserver> observer_;
  ProxyHooks hooks_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  std::vector<std::string> scids_;
  bool closed_ = false;
  // Calls into ngtcp2/nghttp3 in progress (CallbackScope), and whether a
  // deferred Flush is queued.
  int callback_depth_ = 0;
  bool flush_posted_ = false;
};

namespace {

ssl_select_cert_result_t SelectCertificate(
    const SSL_CLIENT_HELLO* client_hello) {
  QuicConnection* connection = QuicConnection::FromSsl(client_hello->ssl);
  return connection != nullptr && connection->OnClientHello(client_hello)
             ? ssl_select_cert_success
             : ssl_select_cert_error;
}

int SelectAlpn(SSL* /*ssl*/, const uint8_t** out, uint8_t* out_length,
               const uint8_t* in, unsigned in_length, void* /*arg*/) {
  for (unsigned i = 0; i < in_length;) {
    const uint8_t length = in[i];
    if (i + 1 + length > in_length) break;
    if (std::string_view(reinterpret_cast<const char*>(in + i + 1), length) ==
        "h3") {
      *out = in + i + 1;
      *out_length = length;
      return SSL_TLSEXT_ERR_OK;
    }
    i += 1 + length;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

}  // namespace

QuicServer::QuicServer(asio::io_context& io_context,
                       const GatewayContext& context, QuicSettings settings)
    : io_context_(io_context),
      context_(context),
      settings_(settings),
      socket_(io_context) {
  RandomBytes(secret_.data(), secret_.size());
  ssl_context_ = SSL_CTX_new(TLS_method());
  ngtcp2_crypto_boringssl_configure_server_context(ssl_context_);
  SSL_CTX_set_select_certificate_cb(ssl_context_, &SelectCertificate);
  SSL_CTX_set_alpn_select_cb(ssl_context_, &SelectAlpn, nullptr);
}

QuicServer::~QuicServer() {
  try {
    Stop();
  } catch (...) {
    // Destructors must not throw; plain stdio cannot throw again.
    std::fputs("quic: error while closing connections\n", stderr);
  }
  SSL_CTX_free(ssl_context_);
}

bool QuicServer::Listen(const asio::ip::udp::endpoint& endpoint,
                        bool reuse_port, std::string* error) {
  std::error_code ec;
  socket_.open(endpoint.protocol(), ec);
  if (!ec && reuse_port && !EnableReusePort(socket_.native_handle())) {
    *error = std::format("SO_REUSEPORT on udp {}", endpoint.port());
    return false;
  }
  if (!ec) socket_.bind(endpoint, ec);
  if (ec) {
    *error = std::format("udp {}: {}", endpoint.port(), ec.message());
    return false;
  }
  local_ = socket_.local_endpoint(ec);
  return true;
}

void QuicServer::Start() {
  asio::co_spawn(io_context_, ReceiveLoop(), asio::detached);
}

void QuicServer::Stop() {
  if (stopped_) return;
  stopped_ = true;
  std::error_code ec;
  socket_.close(ec);
  // Close() removes each connection from the map.
  while (!connections_.empty()) {
    const std::shared_ptr<QuicConnection> connection =
        connections_.begin()->second;
    ngtcp2_ccerr error;
    ngtcp2_ccerr_default(&error);
    connection->Close(&error);
    if (connections_.erase(connection.get()) > 0) {
      GlobalMetrics().quic_connections.Add(-1);
    }
  }
  by_cid_.clear();
}

asio::awaitable<void> QuicServer::ReceiveLoop() {
  std::vector<uint8_t> buffer(std::size_t{64} * 1024);
  asio::ip::udp::endpoint remote;
  while (!stopped_) {
    auto [ec, n] = co_await socket_.async_receive_from(
        asio::buffer(buffer), remote, asio::as_tuple(asio::use_awaitable));
    if (ec) {
      if (!socket_.is_open()) co_return;
      continue;
    }
    GlobalMetrics().quic_datagrams.Inc();
    OnDatagram(std::span(buffer.data(), n), remote);
  }
}

void QuicServer::OnDatagram(std::span<const uint8_t> data,
                            const asio::ip::udp::endpoint& remote) {
  ngtcp2_version_cid vc;
  const int rv =
      ngtcp2_pkt_decode_version_cid(&vc, data.data(), data.size(), kCidLength);
  if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
    SendVersionNegotiation(std::span(vc.scid, vc.scidlen),
                           std::span(vc.dcid, vc.dcidlen), remote);
    return;
  }
  if (rv != 0) return;
  if (const auto it = by_cid_.find(CidKey(vc.dcid, vc.dcidlen));
      it != by_cid_.end()) {
    // Keep it alive: the callbacks may remove it from the maps.
    const std::shared_ptr<QuicConnection> connection = it->second;
    connection->OnDatagram(data, remote);
    return;
  }
  ngtcp2_pkt_hd header;
  if (ngtcp2_accept(&header, data.data(), data.size()) != 0) return;
  if (connections_.size() >= settings_.max_connections) {
    GlobalMetrics().quic_rejected.Inc();
    return;
  }
  ngtcp2_cid original_dcid;
  const ngtcp2_cid* odcid = nullptr;
  if (settings_.retry) {
    if (header.tokenlen == 0 ||
        header.token[0] != NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) {
      SendRetry(&header, remote);
      return;
    }
    if (ngtcp2_crypto_verify_retry_token2(
            &original_dcid, header.token, header.tokenlen, secret_.data(),
            secret_.size(), header.version,
            reinterpret_cast<const ngtcp2_sockaddr*>(remote.data()),
            static_cast<ngtcp2_socklen>(remote.size()), &header.dcid,
            10 * NGTCP2_SECONDS, Now()) != 0) {
      GlobalMetrics().quic_rejected.Inc();
      return;
    }
    odcid = &original_dcid;
  }
  auto connection = std::make_shared<QuicConnection>(this, remote, local_);
  connections_[connection.get()] = connection;
  GlobalMetrics().quic_connections.Add(1);
  if (!connection->Init(header, odcid)) {
    Remove(connection.get());
    return;
  }
  // The client keeps sending to the DCID it chose (or the Retry SCID)
  // until it sees ours, e.g. a ClientHello split over two Initials (large
  // post-quantum key shares): without this the second one would make a
  // second connection, which then holds a max_connections slot until the
  // idle timeout. Dropped with the connection's other ids in Remove().
  Register(CidKey(header.dcid), connection);
  connection->OnDatagram(data, remote);
}

void QuicServer::SendVersionNegotiation(std::span<const uint8_t> dcid,
                                        std::span<const uint8_t> scid,
                                        const asio::ip::udp::endpoint& remote) {
  const std::array<uint32_t, 1> versions = {NGTCP2_PROTO_VER_V1};
  std::array<uint8_t, kMaxPacket> buffer{};
  uint8_t unused = 0;
  RandomBytes(&unused, 1);
  const ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(
      buffer.data(), buffer.size(), unused, dcid.data(), dcid.size(),
      scid.data(), scid.size(), versions.data(), versions.size());
  if (n > 0) {
    Send(remote, std::span(buffer.data(), static_cast<std::size_t>(n)));
  }
}

void QuicServer::SendRetry(const void* header_pointer,
                           const asio::ip::udp::endpoint& remote) {
  const auto& header = *static_cast<const ngtcp2_pkt_hd*>(header_pointer);
  ngtcp2_cid scid;
  scid.datalen = kCidLength;
  RandomBytes(scid.data, scid.datalen);
  std::array<uint8_t, NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2> token{};
  const ngtcp2_ssize token_length = ngtcp2_crypto_generate_retry_token2(
      token.data(), secret_.data(), secret_.size(), header.version,
      reinterpret_cast<const ngtcp2_sockaddr*>(remote.data()),
      static_cast<ngtcp2_socklen>(remote.size()), &scid, &header.dcid, Now());
  if (token_length < 0) return;
  std::array<uint8_t, kMaxPacket> buffer{};
  const ngtcp2_ssize n = ngtcp2_crypto_write_retry(
      buffer.data(), buffer.size(), header.version, &header.scid, &scid,
      &header.dcid, token.data(), static_cast<std::size_t>(token_length));
  if (n > 0) {
    GlobalMetrics().quic_retries.Inc();
    Send(remote, std::span(buffer.data(), static_cast<std::size_t>(n)));
  }
}

void QuicServer::Send(const asio::ip::udp::endpoint& remote,
                      std::span<const uint8_t> packet) {
  std::error_code ec;
  socket_.send_to(asio::buffer(packet.data(), packet.size()), remote, 0, ec);
  if (ec) GlobalMetrics().quic_send_errors.Inc();
}

void QuicServer::Register(std::string_view cid,
                          const std::shared_ptr<QuicConnection>& connection) {
  by_cid_[std::string(cid)] = connection;
}

void QuicServer::Unregister(std::string_view cid) {
  by_cid_.erase(std::string(cid));
}

void QuicServer::Remove(QuicConnection* connection) {
  // Deferred: the connection may be inside one of its own callbacks. By
  // weak pointer, not address: a second Remove of the same connection may
  // run after a new connection got its address, and must not drop that one.
  asio::post(io_context_, [this, alive = std::weak_ptr<int>(alive_),
                           weak = connection->weak_from_this()] {
    if (alive.expired()) return;
    const std::shared_ptr<QuicConnection> target = weak.lock();
    if (target == nullptr) return;
    std::erase_if(by_cid_, [&target](const auto& entry) {
      return entry.second == target;
    });
    if (connections_.erase(target.get()) > 0) {
      GlobalMetrics().quic_connections.Add(-1);
    }
  });
}

}  // namespace bot_shield
