// Fake Traefik for the end-to-end test.
//
// TLS port: optional PROXY v2 header, then TLS. ALPN h2 -> HTTP/2 server that
// answers every request with a JSON description of it; special paths:
//   /big?bytes=N     N bytes of body
//   /trailers        response with a "grpc-status: 0" trailer
//   /trailers-only   gRPC trailers-only: one HEADERS frame with END_STREAM
//   /status/NNN      that status code
// ALPN http/1.1 or none -> a WebSocket-style upgrade (101 + echo) or "line
// mode": one line in, one key=value line out (used by passthrough checks).
// SNI "noh2.test" never gets h2, to provoke upstream failures.
// Plain port: optional PROXY v2 header, then line mode.
//
// Usage: fake_upstream <tls port> <plain port> <cert.pem> <key.pem>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
// SIGPIPE is POSIX, not part of <csignal>: include-cleaner wants <signal.h>
// on Linux and <sys/signal.h> on macOS.
// NOLINTNEXTLINE(modernize-deprecated-headers)
#include <signal.h>      // IWYU pragma: keep
#include <sys/signal.h>  // IWYU pragma: keep
#include <sys/socket.h>
#include <sys/types.h>  // IWYU pragma: keep (ssize_t on Linux)
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view kProxySignature("\r\n\r\n\0\r\nQUIT\n", 12);

struct ProxyInfo {
  std::string source;  // "ip:port" or "" without a PROXY header.
  std::string authority;
};

int ParseInt(std::string_view text) {
  int value = 0;
  std::from_chars(text.data(), text.data() + text.size(), value);
  return value;
}

bool ReadExact(int fd, char* out, std::size_t size) {
  std::size_t done = 0;
  while (done < size) {
    const ssize_t n = recv(fd, out + done, size - done, 0);
    if (n <= 0) return false;
    done += static_cast<std::size_t>(n);
  }
  return true;
}

// Consumes a PROXY v2 header if the connection starts with one.
bool ReadProxyHeader(int fd, ProxyInfo* info) {
  char peek[12];
  const ssize_t n = recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_WAITALL);
  if (n < 12 || std::string_view(peek, 12) != kProxySignature) return true;
  char header[16];
  if (!ReadExact(fd, header, 16)) return false;
  const std::size_t size = (static_cast<uint8_t>(header[14]) << 8) |
                           static_cast<uint8_t>(header[15]);
  std::string body(size, '\0');
  if (!ReadExact(fd, body.data(), size)) return false;
  char ip[64] = {};
  std::size_t tlv = 0;
  uint16_t port = 0;
  if (header[13] == 0x11) {
    inet_ntop(AF_INET, body.data(), ip, sizeof(ip));
    port = static_cast<uint16_t>((static_cast<uint8_t>(body[8]) << 8) |
                                 static_cast<uint8_t>(body[9]));
    tlv = 12;
  } else {
    inet_ntop(AF_INET6, body.data(), ip, sizeof(ip));
    port = static_cast<uint16_t>((static_cast<uint8_t>(body[32]) << 8) |
                                 static_cast<uint8_t>(body[33]));
    tlv = 36;
  }
  info->source = std::string(ip) + ":" + std::to_string(port);
  while (tlv + 3 <= body.size()) {
    const auto type = static_cast<uint8_t>(body[tlv]);
    const std::size_t length = (static_cast<uint8_t>(body[tlv + 1]) << 8) |
                               static_cast<uint8_t>(body[tlv + 2]);
    if (type == 0x02) info->authority = body.substr(tlv + 3, length);
    tlv += 3 + length;
  }
  return true;
}

std::string LineReply(std::string_view transport, const ProxyInfo& proxy,
                      std::string_view sni, std::string_view alpn,
                      std::string line) {
  for (char& c : line) {
    if (c == ' ') c = '_';
  }
  if (line.empty()) line = "-";
  return std::string("upstream=") + std::string(transport) +
         " src=" + (proxy.source.empty() ? "-" : proxy.source) +
         " sni=" + (sni.empty() ? "-" : std::string(sni)) +
         " alpn=" + (alpn.empty() ? "-" : std::string(alpn)) +
         " authority=" + (proxy.authority.empty() ? "-" : proxy.authority) +
         " got=" + line + "\n";
}

// --- HTTP/2 -----------------------------------------------------------------

struct H2Request {
  std::map<std::string, std::string> headers;
  std::string body;
  std::string response;
  std::size_t offset = 0;
  bool trailers = false;
};

struct H2Session {
  SSL* ssl = nullptr;
  std::string sni;
  ProxyInfo proxy;
  std::map<int32_t, H2Request> requests;
};

nghttp2_ssize SendCallback(nghttp2_session*, const uint8_t* data,
                           std::size_t size, int, void* user_data) {
  auto* session = static_cast<H2Session*>(user_data);
  const int n = SSL_write(session->ssl, data, static_cast<int>(size));
  return n <= 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : n;
}

nghttp2_ssize ReadBody(nghttp2_session* session, int32_t stream_id,
                       uint8_t* buffer, std::size_t size, uint32_t* flags,
                       nghttp2_data_source*, void* user_data) {
  auto* state = static_cast<H2Session*>(user_data);
  H2Request& request = state->requests[stream_id];
  const std::size_t n =
      std::min(size, request.response.size() - request.offset);
  std::copy_n(request.response.data() + request.offset, n, buffer);
  request.offset += n;
  if (request.offset == request.response.size()) {
    *flags |= NGHTTP2_DATA_FLAG_EOF;
    if (request.trailers) {
      *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      static const char kName[] = "grpc-status";
      static const char kValue[] = "0";
      nghttp2_nv trailer = {
          reinterpret_cast<uint8_t*>(const_cast<char*>(kName)),
          reinterpret_cast<uint8_t*>(const_cast<char*>(kValue)),
          sizeof(kName) - 1, sizeof(kValue) - 1, NGHTTP2_NV_FLAG_NONE};
      nghttp2_submit_trailer(session, stream_id, &trailer, 1);
    }
  }
  return static_cast<nghttp2_ssize>(n);
}

void Respond(nghttp2_session* session, H2Session* state, int32_t stream_id) {
  H2Request& request = state->requests[stream_id];
  const std::string path = request.headers[":path"];
  int status = 200;
  std::string content_type = "application/json";
  if (path == "/trailers-only") {
    std::vector<std::pair<std::string, std::string>> headers = {
        {":status", "200"},
        {"content-type", "application/grpc"},
        {"grpc-status", "12"},
        {"grpc-message", "unimplemented"}};
    std::vector<nghttp2_nv> nva;
    nva.reserve(headers.size());
    for (auto& [name, value] : headers) {
      nva.push_back({reinterpret_cast<uint8_t*>(name.data()),
                     reinterpret_cast<uint8_t*>(value.data()), name.size(),
                     value.size(), NGHTTP2_NV_FLAG_NONE});
    }
    nghttp2_submit_response2(session, stream_id, nva.data(), nva.size(),
                             nullptr);
    return;
  }
  if (path.starts_with("/big?bytes=")) {
    request.response.assign(static_cast<std::size_t>(ParseInt(path.substr(11))),
                            'x');
    content_type = "application/octet-stream";
  } else {
    if (path.starts_with("/status/")) {
      status = ParseInt(path.substr(8));
    }
    request.trailers = path == "/trailers";
    nlohmann::json json = {{"proto", "h2"},
                           {"sni", state->sni},
                           {"proxy_src", state->proxy.source},
                           {"body_len", request.body.size()},
                           {"headers", request.headers}};
    request.response = json.dump();
  }
  const std::string status_text = std::to_string(status);
  const std::string length = std::to_string(request.response.size());
  std::vector<std::pair<std::string, std::string>> headers = {
      {":status", status_text}, {"content-type", content_type}};
  if (!request.trailers) headers.emplace_back("content-length", length);
  std::vector<nghttp2_nv> nva;
  nva.reserve(headers.size());
  for (auto& [name, value] : headers) {
    nva.push_back({reinterpret_cast<uint8_t*>(name.data()),
                   reinterpret_cast<uint8_t*>(value.data()), name.size(),
                   value.size(), NGHTTP2_NV_FLAG_NONE});
  }
  nghttp2_data_provider2 provider{};
  provider.read_callback = &ReadBody;
  nghttp2_submit_response2(session, stream_id, nva.data(), nva.size(),
                           &provider);
}

int OnBeginHeaders(nghttp2_session*, const nghttp2_frame* frame,
                   void* user_data) {
  auto* state = static_cast<H2Session*>(user_data);
  if (frame->hd.type == NGHTTP2_HEADERS &&
      frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    state->requests[frame->hd.stream_id] = H2Request{};
  }
  return 0;
}

int OnHeader(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name,
             std::size_t name_size, const uint8_t* value,
             std::size_t value_size, uint8_t, void* user_data) {
  auto* state = static_cast<H2Session*>(user_data);
  auto it = state->requests.find(frame->hd.stream_id);
  if (it == state->requests.end()) return 0;
  std::string key(reinterpret_cast<const char*>(name), name_size);
  std::string text(reinterpret_cast<const char*>(value), value_size);
  auto& slot = it->second.headers[key];
  slot = slot.empty() ? text : slot + ", " + text;
  return 0;
}

int OnDataChunk(nghttp2_session*, uint8_t, int32_t stream_id,
                const uint8_t* data, std::size_t size, void* user_data) {
  auto* state = static_cast<H2Session*>(user_data);
  state->requests[stream_id].body.append(reinterpret_cast<const char*>(data),
                                         size);
  return 0;
}

int OnFrameRecv(nghttp2_session* session, const nghttp2_frame* frame,
                void* user_data) {
  auto* state = static_cast<H2Session*>(user_data);
  if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
      (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0 &&
      state->requests.contains(frame->hd.stream_id)) {
    Respond(session, state, frame->hd.stream_id);
  }
  return 0;
}

int OnStreamClose(nghttp2_session*, int32_t stream_id, uint32_t,
                  void* user_data) {
  static_cast<H2Session*>(user_data)->requests.erase(stream_id);
  return 0;
}

void ServeH2(SSL* ssl, std::string sni, ProxyInfo proxy) {
  H2Session state;
  state.ssl = ssl;
  state.sni = std::move(sni);
  state.proxy = std::move(proxy);
  nghttp2_session_callbacks* callbacks = nullptr;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback2(callbacks, &SendCallback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          &OnBeginHeaders);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, &OnHeader);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                            &OnDataChunk);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &OnFrameRecv);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                         &OnStreamClose);
  nghttp2_session* session = nullptr;
  nghttp2_session_server_new(&session, callbacks, &state);
  nghttp2_session_callbacks_del(callbacks);
  nghttp2_settings_entry settings[] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 250}};
  nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, 1);
  nghttp2_session_send(session);
  std::vector<uint8_t> buffer(16384);
  while (nghttp2_session_want_read(session) ||
         nghttp2_session_want_write(session)) {
    const int n = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
    if (n <= 0) break;
    if (nghttp2_session_mem_recv2(session, buffer.data(),
                                  static_cast<std::size_t>(n)) < 0) {
      break;
    }
    if (nghttp2_session_send(session) != 0) break;
  }
  nghttp2_session_del(session);
}

// --- HTTP/1.1 and line mode ------------------------------------------------

void ServeH1(SSL* ssl, const std::string& sni, std::string_view alpn,
             const ProxyInfo& proxy) {
  std::string data;
  char buffer[4096];
  while (data.find('\n') == std::string::npos) {
    const int n = SSL_read(ssl, buffer, sizeof(buffer));
    if (n <= 0) return;
    data.append(buffer, static_cast<std::size_t>(n));
  }
  std::string lower = data;
  for (char& c : lower) c = static_cast<char>(std::tolower(c));
  if (lower.find("upgrade: websocket") != std::string::npos) {
    while (data.find("\r\n\r\n") == std::string::npos) {
      const int n = SSL_read(ssl, buffer, sizeof(buffer));
      if (n <= 0) return;
      data.append(buffer, static_cast<std::size_t>(n));
    }
    std::string xff;
    const auto at = lower.find("x-forwarded-for: ");
    if (at != std::string::npos) {
      xff = data.substr(at + 17, data.find("\r\n", at) - at - 17);
    }
    const std::string reply =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nX-Seen-Forwarded-For: " +
        xff + "\r\n\r\n";
    SSL_write(ssl, reply.data(), static_cast<int>(reply.size()));
    // Echo whatever follows the request head.
    std::string rest = data.substr(data.find("\r\n\r\n") + 4);
    if (!rest.empty()) {
      SSL_write(ssl, rest.data(), static_cast<int>(rest.size()));
    }
    while (true) {
      const int n = SSL_read(ssl, buffer, sizeof(buffer));
      if (n <= 0) return;
      SSL_write(ssl, buffer, n);
    }
  }
  const std::string reply =
      LineReply("tls", proxy, sni, alpn, data.substr(0, data.find('\n')));
  SSL_write(ssl, reply.data(), static_cast<int>(reply.size()));
}

int SelectAlpn(SSL* ssl, const uint8_t** out, uint8_t* out_size,
               const uint8_t* in, unsigned in_size, void*) {
  const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  const bool allow_h2 = sni == nullptr || std::string_view(sni) != "noh2.test";
  for (std::string_view wanted : {"h2", "http/1.1", "acme-tls/1"}) {
    if (wanted == "h2" && !allow_h2) continue;
    for (unsigned i = 0; i < in_size; i += 1 + in[i]) {
      if (std::string_view(reinterpret_cast<const char*>(in + i + 1), in[i]) ==
          wanted) {
        *out = in + i + 1;
        *out_size = in[i];
        return SSL_TLSEXT_ERR_OK;
      }
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}

void ServeTls(int fd, SSL_CTX* ctx) {
  ProxyInfo proxy;
  if (!ReadProxyHeader(fd, &proxy)) {
    close(fd);
    return;
  }
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  if (SSL_accept(ssl) == 1) {
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const uint8_t* alpn_data = nullptr;
    unsigned alpn_size = 0;
    SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_size);
    const std::string alpn(reinterpret_cast<const char*>(alpn_data), alpn_size);
    if (alpn == "h2") {
      ServeH2(ssl, sni ? sni : "", proxy);
    } else {
      ServeH1(ssl, sni ? sni : "", alpn, proxy);
    }
    SSL_shutdown(ssl);
  }
  SSL_free(ssl);
  close(fd);
}

void ServePlain(int fd) {
  ProxyInfo proxy;
  if (ReadProxyHeader(fd, &proxy)) {
    std::string data;
    char buffer[4096];
    while (data.find('\n') == std::string::npos) {
      const ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
      if (n <= 0) break;
      data.append(buffer, static_cast<std::size_t>(n));
    }
    const std::string reply =
        LineReply("plain", proxy, "", "", data.substr(0, data.find('\n')));
    send(fd, reply.data(), reply.size(), 0);
  }
  close(fd);
}

int Listen(uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  const int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
      listen(fd, 128) != 0) {
    std::perror("listen");
    std::exit(1);
  }
  return fd;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 5) {
    std::fprintf(stderr, "usage: %s TLS_PORT PLAIN_PORT CERT KEY\n", argv[0]);
    return 2;
  }
  std::signal(SIGPIPE, SIG_IGN);
  SSL_CTX* ctx = SSL_CTX_new(TLS_method());
  if (SSL_CTX_use_certificate_chain_file(ctx, argv[3]) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  SSL_CTX_set_alpn_select_cb(ctx, &SelectAlpn, nullptr);
  const int tls = Listen(static_cast<uint16_t>(ParseInt(argv[1])));
  const int plain = Listen(static_cast<uint16_t>(ParseInt(argv[2])));
  std::thread([plain] {
    while (true) {
      const int fd = accept(plain, nullptr, nullptr);
      if (fd >= 0) std::thread(ServePlain, fd).detach();
    }
  }).detach();
  while (true) {
    const int fd = accept(tls, nullptr, nullptr);
    if (fd >= 0) std::thread(ServeTls, fd, ctx).detach();
  }
}
