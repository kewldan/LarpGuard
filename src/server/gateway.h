#ifndef BOT_SHIELD_SERVER_GATEWAY_H_
#define BOT_SHIELD_SERVER_GATEWAY_H_

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/ssl/context.hpp>
#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/server.h"
#include "config/config.h"
#include "docker/labels.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "fp/library.h"
#include "net/classifier.h"
#include "proxy/upstream_pool.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "score/rules.h"
#include "score/scorer.h"
#include "server/connection.h"
#include "tls/cert_store.h"

namespace bot_shield {

// One event loop on one thread. On Linux every worker has its own listening
// sockets (SO_REUSEPORT) so the kernel spreads connections across workers and
// no state is shared on the hot path.
class Worker {
 public:
  Worker(int index, GatewayContext shared, const Config& config);

  Worker(const Worker&) = delete;
  Worker& operator=(const Worker&) = delete;

  // Binds this worker's listeners. Must be called before Run().
  bool Listen(const asio::ip::tcp::endpoint& https,
              const std::optional<asio::ip::tcp::endpoint>& http,
              bool reuse_port, std::string* error);
  bool ListenMetrics(const asio::ip::tcp::endpoint& endpoint,
                     std::string* error);
  bool ListenAdmin(const std::string& path, const AdminContext& admin,
                   std::string* error);

  void Run();
  // Stops accepting; open connections keep running until they finish.
  void StopAccepting();
  // Stops the event loop, abandoning open connections.
  void Stop();
  void Join();
  bool finished() const { return finished_.load(); }

 private:
  void StartAccepting(asio::ip::tcp::acceptor* acceptor, bool https);

  const int index_;
  asio::io_context io_context_;
  asio::ssl::context upstream_tls_;
  GatewayContext context_;
  std::vector<std::unique_ptr<asio::ip::tcp::acceptor>> acceptors_;
  std::unique_ptr<asio::local::stream_protocol::acceptor> admin_acceptor_;
  std::unique_ptr<UpstreamPool> pool_;
  std::thread thread_;
  std::atomic<bool> finished_{false};
};

// Long-lived objects the gateway uses but does not own (main owns them).
struct GatewayServices {
  EventSink* events = nullptr;  // Null: events off.
  const EventSettings* event_settings = nullptr;
  const FingerprintLibrary* library = nullptr;
  const LabelStore* labels = nullptr;  // Null: Docker off.
  ListStore* lists = nullptr;
  DecisionLog* decisions = nullptr;
  const Challenger* challenger = nullptr;
};

class Gateway {
 public:
  // `events` may be null (events disabled); both must outlive the gateway.
  Gateway(const Config& config, const CertStore* certificates,
          const GatewayServices& services);
  ~Gateway();

  Gateway(const Gateway&) = delete;
  Gateway& operator=(const Gateway&) = delete;

  bool Start(std::string* error);
  void StopAccepting();
  void Stop();
  void Join();
  bool finished() const;
  int worker_count() const { return static_cast<int>(workers_.size()); }

 private:
  const Config& config_;
  const CertStore* certificates_;
  Classifier classifier_;
  Scorer scorer_;
  Policy policy_;
  RuleSet rules_;
  GatewayServices services_;
  AdminContext admin_;
  RateLimitSet rate_limits_;
  RateLimitStore rate_limit_store_;
  ConnectionCounter connection_counter_;
  std::vector<std::unique_ptr<Worker>> workers_;
};

// Resolves "host:port" to an address. Names are resolved once at startup.
bool ResolveEndpoint(const Endpoint& endpoint, asio::ip::tcp::endpoint* out,
                     std::string* error);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_GATEWAY_H_
