#ifndef BOT_SHIELD_ADMIN_SERVER_H_
#define BOT_SHIELD_ADMIN_SERVER_H_

#include <asio/awaitable.hpp>
#include <asio/local/stream_protocol.hpp>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "admin/decision_log.h"
#include "admin/lists.h"
#include "config/config.h"
#include "docker/labels.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "tls/cert_store.h"

namespace bot_shield {

// What the admin API reads and changes. Owned by the gateway and main.
struct AdminContext {
  const Config* config = nullptr;
  const CertStore* certificates = nullptr;
  const LabelStore* labels = nullptr;  // May be null.
  ListStore* lists = nullptr;
  const DecisionLog* decisions = nullptr;
  const RateLimitStore* rate_limit_store = nullptr;
  const RateLimitSet* rate_limits = nullptr;
  const Policy* policy = nullptr;
  int64_t started_ms = 0;
  int workers = 0;
};

struct AdminResponse {
  int status = 200;
  nlohmann::json body;
};

// Routes one request (exposed for tests):
//   GET    /status
//   GET    /policy?host=<host>
//   GET    /lists            POST /lists        DELETE /lists/<id>
//   GET    /decisions?limit=&host=&class=       GET /decisions/<request id>
AdminResponse HandleAdminRequest(std::string_view method,
                                 std::string_view target, std::string_view body,
                                 const AdminContext& context,
                                 int64_t now_seconds);

// Binds the admin socket (an old socket file is replaced) with mode 0600.
bool OpenAdminSocket(asio::local::stream_protocol::acceptor* acceptor,
                     const std::string& path, std::string* error);

// HTTP/1.1 over the unix socket, one request per connection.
asio::awaitable<void> ServeAdmin(
    asio::local::stream_protocol::acceptor& acceptor,
    const AdminContext& context);

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_SERVER_H_
