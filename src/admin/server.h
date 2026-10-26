#ifndef BOT_SHIELD_ADMIN_SERVER_H_
#define BOT_SHIELD_ADMIN_SERVER_H_

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/local/stream_protocol.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <thread>

#include "admin/attack.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/modes.h"
#include "admin/settings.h"
#include "config/config.h"
#include "docker/labels.h"
#include "events/events.h"
#include "net/asn.h"
#include "ratelimit/store.h"
#include "server/verdicts.h"
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
  // Policy, rules, limits and library; replaced on reload.
  const VerdictStore* verdicts = nullptr;
  // Re-reads the configuration (POST /reload); null: not available.
  std::function<bool(std::string* summary)> reload;
  AttackMode* attack = nullptr;  // May be null.
  // Salt of ip_hash in events, so decisions carry the same hash; may be null.
  const EventSettings* event_settings = nullptr;
  // Host modes from POST /policy; null: not available. `publish_modes`
  // rebuilds the verdict set with them (serialized with reloads).
  ModeOverrides* modes = nullptr;
  std::function<void()> publish_modes;
  const AsnStore* asn = nullptr;  // May be null.
  // The console's settings layer (ADR-018); null: not available.
  // `apply_settings` builds the verdict set from `config`, runs `commit` and
  // publishes the set only when both succeed (serialized with reloads).
  SettingsLayer* settings = nullptr;
  std::function<bool(const Config& config, const std::function<bool()>& commit,
                     std::string* error)>
      apply_settings;
  int64_t started_ms = 0;
  int workers = 0;
};

struct AdminResponse {
  int status = 200;
  nlohmann::json body;
};

// Routes one request (exposed for tests):
//   GET    /status
//   GET    /config           (the verdict set in effect, without secrets)
//   GET    /policy[?host=<host>]
//   POST   /policy           DELETE /policy/<host>   (console host modes)
//   GET    /lists            POST /lists        PATCH|DELETE /lists/<id>
//   GET    /decisions?limit=&host=&class=       GET /decisions/<request id>
//   GET    /attack           POST /attack       DELETE /attack/<host>
//   POST   /rules/test       (a condition on sample events)
//   GET    /asn?numbers=<n>,<n>
//   POST   /reload           (rules, limits, policy, library, model)
//   GET    /settings         POST /settings     POST /settings/validate
//   GET    /settings/history POST /settings/rollback   (ADR-018)
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

// The admin API on its own thread and event loop, off the workers: some
// requests (POST /rules/test) do real CPU work. Everything AdminContext
// points to is thread-safe already, since workers use it concurrently.
class AdminServer {
 public:
  AdminServer() = default;
  ~AdminServer();

  AdminServer(const AdminServer&) = delete;
  AdminServer& operator=(const AdminServer&) = delete;

  // Binds `path` and starts serving; `context` must outlive the server.
  bool Start(const std::string& path, const AdminContext* context,
             std::string* error);
  // Closes the socket; requests in progress finish.
  void StopAccepting();
  void Stop();
  void Join();

 private:
  asio::io_context io_context_;
  std::unique_ptr<asio::local::stream_protocol::acceptor> acceptor_;
  std::thread thread_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_SERVER_H_
