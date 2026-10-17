#ifndef BOT_SHIELD_NET_CLASSIFIER_H_
#define BOT_SHIELD_NET_CLASSIFIER_H_

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "config/config.h"
#include "tls/cert_store.h"
#include "tls/client_hello.h"

namespace bot_shield {

enum class Route {
  // Terminate TLS here and proxy the plaintext to Traefik over TLS.
  kTerminate,
  // Forward the raw TCP stream to Traefik untouched.
  kPassthrough,
  // Close the connection.
  kReject,
};

enum class RouteReason {
  kCertificate,
  kAcmeTlsAlpn,
  kNoServerName,
  kPassthroughPolicy,
  kNoCertificate,
  kNotTls,
  kInvalidHello,
};

std::string_view RouteName(Route route);
std::string_view RouteReasonName(RouteReason reason);

struct RouteDecision {
  Route route = Route::kReject;
  RouteReason reason = RouteReason::kInvalidHello;
  // Set for kTerminate.
  std::shared_ptr<const CertEntry> certificate;
};

// Decides, from the ClientHello alone, whether a connection is terminated
// here or handed to Traefik as is. Anything we cannot serve correctly goes to
// Traefik, so adding the gateway never breaks a site.
class Classifier {
 public:
  Classifier(std::vector<std::string> passthrough_hosts, NonTlsAction non_tls);

  RouteDecision Classify(ParseStatus status, const ClientHello& hello,
                         const CertSnapshot& certificates) const;

 private:
  bool IsPassthroughHost(std::string_view host) const;

  std::vector<std::string> passthrough_hosts_;
  NonTlsAction non_tls_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_NET_CLASSIFIER_H_
