#include "fp/h2_fingerprint.h"

#include <cstdint>
#include <format>
#include <string>
#include <utility>
#include <vector>

namespace bot_shield {

void H2FingerprintBuilder::OnSettings(
    const std::vector<std::pair<uint16_t, uint32_t>>& settings) {
  if (settings_seen_ || complete_) return;
  settings_seen_ = true;
  for (const auto& [id, value] : settings) {
    if (!settings_.empty()) settings_.push_back(';');
    settings_ += std::format("{}:{}", id, value);
  }
}

void H2FingerprintBuilder::OnWindowUpdate(uint32_t stream_id,
                                          uint32_t increment) {
  if (complete_ || stream_id != 0 || !window_update_.empty()) return;
  window_update_ = std::to_string(increment);
}

void H2FingerprintBuilder::OnPriority(uint32_t stream_id, bool exclusive,
                                      uint32_t dependency, int weight) {
  if (complete_) return;
  priorities_.push_back(std::format("{}:{}:{}:{}", stream_id, exclusive ? 1 : 0,
                                    dependency, weight));
}

void H2FingerprintBuilder::OnFirstRequest(
    const std::vector<std::string>& pseudo_header_order) {
  if (complete_) return;
  complete_ = true;
  std::string pseudo;
  for (const std::string& name : pseudo_header_order) {
    if (!pseudo.empty()) pseudo.push_back(',');
    pseudo.push_back(name.size() > 1 ? name[1] : '?');
  }
  std::string priorities;
  for (const std::string& priority : priorities_) {
    if (!priorities.empty()) priorities.push_back(',');
    priorities += priority;
  }
  fingerprint_ = std::format("{}|{}|{}|{}", settings_,
                             window_update_.empty() ? "00" : window_update_,
                             priorities.empty() ? "0" : priorities, pseudo);
}

}  // namespace bot_shield
