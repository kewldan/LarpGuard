#ifndef BOT_SHIELD_FP_H2_FINGERPRINT_H_
#define BOT_SHIELD_FP_H2_FINGERPRINT_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace bot_shield {

// Builds the HTTP/2 client fingerprint in the public Akamai format from the
// frames a client sends before its first request:
//   SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order
//   e.g. 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
class H2FingerprintBuilder {
 public:
  // The first non-ACK SETTINGS frame, entries in wire order.
  void OnSettings(const std::vector<std::pair<uint16_t, uint32_t>>& settings);
  void OnWindowUpdate(uint32_t stream_id, uint32_t increment);
  // `weight` is the actual weight, 1..256.
  void OnPriority(uint32_t stream_id, bool exclusive, uint32_t dependency,
                  int weight);
  // Pseudo-header names of the first request, e.g. ":method".
  void OnFirstRequest(const std::vector<std::string>& pseudo_header_order);

  bool complete() const { return complete_; }
  // Empty until OnFirstRequest().
  const std::string& fingerprint() const { return fingerprint_; }

 private:
  bool settings_seen_ = false;
  bool complete_ = false;
  std::string settings_;
  std::string window_update_;
  std::vector<std::string> priorities_;
  std::string fingerprint_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_FP_H2_FINGERPRINT_H_
