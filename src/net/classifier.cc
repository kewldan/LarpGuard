#include "net/classifier.h"

#include <algorithm>
#include <utility>

#include "common/host.h"

namespace bot_shield {

std::string_view RouteName(Route route) {
  switch (route) {
    case Route::kTerminate:
      return "terminate";
    case Route::kPassthrough:
      return "passthrough";
    case Route::kReject:
      return "reject";
  }
  return "?";
}

std::string_view RouteReasonName(RouteReason reason) {
  switch (reason) {
    case RouteReason::kCertificate:
      return "certificate";
    case RouteReason::kAcmeTlsAlpn:
      return "acme_tls_alpn";
    case RouteReason::kNoServerName:
      return "no_server_name";
    case RouteReason::kPassthroughPolicy:
      return "policy";
    case RouteReason::kNoCertificate:
      return "no_certificate";
    case RouteReason::kNotTls:
      return "not_tls";
    case RouteReason::kInvalidHello:
      return "invalid_client_hello";
  }
  return "?";
}

Classifier::Classifier(std::vector<std::string> passthrough_hosts,
                       NonTlsAction non_tls)
    : passthrough_hosts_(std::move(passthrough_hosts)), non_tls_(non_tls) {
  for (std::string& host : passthrough_hosts_) host = NormalizeHost(host);
}

RouteDecision Classifier::Classify(ParseStatus status, const ClientHello& hello,
                                   const CertSnapshot& certificates) const {
  switch (status) {
    case ParseStatus::kOk:
      break;
    case ParseStatus::kNotTls:
      return {non_tls_ == NonTlsAction::kPassthrough ? Route::kPassthrough
                                                     : Route::kReject,
              RouteReason::kNotTls, nullptr};
    case ParseStatus::kNeedMore:
    case ParseStatus::kInvalid:
      return {Route::kReject, RouteReason::kInvalidHello, nullptr};
  }

  // TLS-ALPN-01 challenges are answered by Traefik's ACME client.
  if (hello.HasAlpn("acme-tls/1")) {
    return {Route::kPassthrough, RouteReason::kAcmeTlsAlpn, nullptr};
  }
  if (hello.server_name.empty()) {
    return {Route::kPassthrough, RouteReason::kNoServerName, nullptr};
  }
  if (IsPassthroughHost(hello.server_name)) {
    return {Route::kPassthrough, RouteReason::kPassthroughPolicy, nullptr};
  }
  auto certificate = certificates.Find(hello.server_name);
  if (!certificate) {
    return {Route::kPassthrough, RouteReason::kNoCertificate, nullptr};
  }
  return {Route::kTerminate, RouteReason::kCertificate, std::move(certificate)};
}

bool Classifier::IsPassthroughHost(std::string_view host) const {
  return std::ranges::any_of(passthrough_hosts_,
                             [host](const std::string& pattern) {
                               return HostMatches(pattern, host);
                             });
}

}  // namespace bot_shield
