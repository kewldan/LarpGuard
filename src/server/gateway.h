#ifndef BOT_SHIELD_SERVER_GATEWAY_H_
#define BOT_SHIELD_SERVER_GATEWAY_H_

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/ssl/context.hpp>
#include <asio/steady_timer.hpp>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "admin/attack.h"
#include "admin/audit_signer.h"
#include "admin/decision_log.h"
#include "admin/lists.h"
#include "admin/modes.h"
#include "admin/server.h"
#include "admin/settings.h"
#include "challenge/captcha.h"
#include "challenge/challenger.h"
#include "config/config.h"
#include "crawler/ranges.h"
#include "crawler/verifier.h"
#include "crawler/web_bot_auth.h"
#include "docker/labels.h"
#include "events/event_sink.h"
#include "events/events.h"
#include "fp/library.h"
#include "net/asn.h"
#include "net/classifier.h"
#include "net/geoip.h"
#include "net/threat_lists.h"
#include "proxy/upstream_pool.h"
#include "quic/h3_server.h"
#include "ratelimit/limits.h"
#include "ratelimit/store.h"
#include "score/policy.h"
#include "score/rules.h"
#include "score/scorer.h"
#include "server/connection.h"
#include "server/health.h"
#include "tls/cert_store.h"
#include "xdp/xdp_filter.h"

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
                     const Heartbeats* heartbeats, std::string* error);

  // Runs the loop on its own thread, beating `heartbeats` from it.
  void Run(Heartbeats* heartbeats);
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
  std::unique_ptr<UpstreamPool> pool_;
  // HTTP/3 listener (http3.enabled).
  std::unique_ptr<QuicServer> quic_;
  // Heartbeat timer; cancelled when draining so the loop can finish.
  asio::steady_timer heartbeat_timer_;
  bool draining_ = false;
  std::thread thread_;
  std::atomic<bool> finished_{false};
};

// Long-lived objects the gateway uses but does not own (main owns them).
struct GatewayServices {
  EventSink* events = nullptr;  // Null: events off.
  const EventSettings* event_settings = nullptr;
  const VerdictStore* verdicts = nullptr;
  // POST /reload in the admin API; may be empty.
  std::function<bool(std::string* summary)> reload;
  // A host switched to under-attack mode by attack.auto_rps (on a worker;
  // must not block); may be empty.
  std::function<void(const AttackEntry& entry)> on_attack_auto;
  // Console host modes (POST /policy) and how to apply them; may be null.
  ModeOverrides* modes = nullptr;
  std::function<void()> publish_modes;
  // The console's settings layer and how to apply a change; may be null.
  SettingsLayer* settings = nullptr;
  std::function<bool(const Config& config, const std::function<bool()>& commit,
                     std::string* error)>
      apply_settings;
  const LabelStore* labels = nullptr;  // Null: Docker off.
  ListStore* lists = nullptr;
  DecisionLog* decisions = nullptr;
  const AuditSigner* audit_signer = nullptr;  // Null: no audit signatures.
  const Challenger* challenger = nullptr;
  Captcha* captcha = nullptr;
  CrawlerVerifier* crawler_verifier = nullptr;
  const CrawlerRangeStore* crawler_ranges = nullptr;
  WebBotAuthVerifier* web_bot_auth = nullptr;
  const AsnStore* asn = nullptr;
  const ThreatListStore* threat_lists = nullptr;  // Null: none enabled.
  const GeoStore* geoip = nullptr;                // Null: geoip.url "".
  XdpAutoBlocks* xdp_blocks = nullptr;
  BehaviorStore* behavior = nullptr;
};

class Gateway {
 public:
  // `events` may be null (events disabled); both must outlive the gateway.
  Gateway(const Config& config, const CertStore* certificates,
          GatewayServices services);
  ~Gateway();

  Gateway(const Gateway&) = delete;
  Gateway& operator=(const Gateway&) = delete;

  bool Start(std::string* error);
  void StopAccepting();
  void Stop();
  void Join();
  bool finished() const;
  // False when a worker loop is stalled (see Heartbeats).
  bool Healthy() const;
  // Writes changed under-attack state to admin.attack_file; blocks, so
  // call it off the workers (main's control loop, once a second).
  void SaveState();
  int worker_count() const { return static_cast<int>(workers_.size()); }

 private:
  const Config& config_;
  const CertStore* certificates_;
  Classifier classifier_;
  GatewayServices services_;
  AdminContext admin_;
  RateLimitStore rate_limit_store_;
  ConnectionCounter connection_counter_;
  ConnectionCounter pending_counter_;
  AttackMode attack_;
  std::unique_ptr<Heartbeats> heartbeats_;
  std::vector<std::unique_ptr<Worker>> workers_;
  // After admin_ and the stores it points to: stopped and joined first.
  std::unique_ptr<AdminServer> admin_server_;
};

// Resolves "host:port" to an address. Names are resolved once at startup.
bool ResolveEndpoint(const Endpoint& endpoint, asio::ip::tcp::endpoint* out,
                     std::string* error);

}  // namespace bot_shield

#endif  // BOT_SHIELD_SERVER_GATEWAY_H_
