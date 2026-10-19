#ifndef BOT_SHIELD_CRAWLER_WEB_BOT_AUTH_H_
#define BOT_SHIELD_CRAWLER_WEB_BOT_AUTH_H_

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "fp/http_request.h"

namespace bot_shield {

// Web Bot Auth (draft-ietf-webbotauth-httpsig-protocol): bots sign requests
// with HTTP Message Signatures (RFC 9421) under tag "web-bot-auth" and name
// where their keys live in Signature-Agent. Only Ed25519 is supported.

// One web-bot-auth signature of a request, ready to verify.
struct WebBotAuthSignature {
  std::string label;
  // Who the signature claims to be: the directory's well-known URI or the
  // jwks_uri without query (the key cache is keyed by it).
  std::string identifier;
  std::string fetch_url;  // What to download for the keys.
  std::string agent;      // Host of `identifier`, for reasons.
  std::string keyid;      // JWK thumbprint (base64url).
  std::string base;       // RFC 9421 signature base.
  std::string signature;  // Raw signature bytes.
  int64_t created = 0;
  int64_t expires = 0;
};

struct WebBotAuthLimits {
  // Signatures valid for longer are not accepted (replay window).
  int64_t max_validity_seconds = int64_t{24} * 3600;
  int64_t clock_skew_seconds = 60;
};

// Web Bot Auth signatures of `request` (none when it carries no
// Signature-Input with tag web-bot-auth). Signatures that cannot be
// checked here (unsupported components or algorithms, expired) are left
// out; `invalid` counts the malformed or expired ones.
std::vector<WebBotAuthSignature> ParseWebBotAuth(const HttpRequest& request,
                                                 int64_t now,
                                                 const WebBotAuthLimits& limits,
                                                 int* invalid);

struct Ed25519Key {
  std::array<uint8_t, 32> public_key{};
  int64_t not_before = 0;  // 0: unset.
  int64_t expires = 0;     // 0: unset.
};

// JWK SHA-256 thumbprint of an Ed25519 key (RFC 7638, RFC 8037 A.3).
std::string Ed25519Thumbprint(const std::array<uint8_t, 32>& public_key);

// Ed25519 keys of a JWK Set, by thumbprint (kid is not trusted).
bool ParseJwks(std::string_view json, std::map<std::string, Ed25519Key>* keys,
               std::string* error);

bool VerifyEd25519(const std::array<uint8_t, 32>& public_key,
                   std::string_view message, std::string_view signature);

enum class WebBotAuthStatus {
  kNone,      // Not signed (or nothing checkable).
  kPending,   // Keys are being fetched; scored like an unsigned request.
  kVerified,  // A signature verified with the agent's published key.
  kInvalid,   // Signed, but the signature is wrong, expired or keyless.
};

struct WebBotAuthResult {
  WebBotAuthStatus status = WebBotAuthStatus::kNone;
  std::string agent;  // Host of the verified (or claimed) agent.
};

// Verifies Web Bot Auth signatures. Key directories are downloaded on
// background threads and cached; the request path only reads the cache, so
// the first request of a new agent is kPending.
class WebBotAuthVerifier {
 public:
  using Fetch = std::function<bool(const std::string& url, std::string* body,
                                   int64_t* max_age, std::string* error)>;

  struct Settings {
    WebBotAuthLimits limits;
    std::chrono::seconds default_ttl{std::chrono::hours(1)};
    std::chrono::seconds max_ttl{std::chrono::hours(24)};
    std::chrono::seconds failed_ttl{std::chrono::minutes(10)};
    std::size_t max_agents = 1000;
    std::size_t max_queue = 256;
  };

  // `fetch` downloads a key set (no redirects); empty = HttpFetch.
  explicit WebBotAuthVerifier(Settings settings, Fetch fetch = {});
  ~WebBotAuthVerifier();
  WebBotAuthVerifier(const WebBotAuthVerifier&) = delete;
  WebBotAuthVerifier& operator=(const WebBotAuthVerifier&) = delete;

  WebBotAuthResult Check(const HttpRequest& request, int64_t now);

  // Blocks until no fetch is queued or running (tests).
  void WaitIdle();

 private:
  struct Directory {
    std::map<std::string, Ed25519Key> keys;  // By thumbprint.
    int64_t expires = 0;
    bool failed = false;
  };

  void Run(const std::stop_token& stop);
  void Enqueue(const WebBotAuthSignature& signature);

  Settings settings_;
  Fetch fetch_;
  std::mutex mutex_;
  std::condition_variable_any wake_;
  std::condition_variable_any idle_;
  std::deque<std::pair<std::string, std::string>> queue_;  // id, url.
  std::set<std::string, std::less<>> in_flight_;
  std::map<std::string, Directory, std::less<>> directories_;
  int running_ = 0;
  std::jthread thread_;  // Last: joined first.
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_CRAWLER_WEB_BOT_AUTH_H_
