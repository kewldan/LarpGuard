#include "model/gbdt.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <fstream>
#include <nlohmann/json.hpp>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "model/features.h"

namespace bot_shield {
namespace {

constexpr std::size_t kMaxTrees = 5000;
constexpr std::size_t kMaxNodes = 1 << 16;

template <typename T>
bool ReadArray(const nlohmann::json& tree, const char* key, std::size_t size,
               std::vector<T>* out) {
  const auto it = tree.find(key);
  if (it == tree.end() || !it->is_array() ||
      (size != 0 && it->size() != size)) {
    return false;
  }
  out->clear();
  for (const auto& item : *it) {
    if (!item.is_number()) return false;
    out->push_back(item.get<T>());
  }
  return true;
}

}  // namespace

bool GbdtModel::Load(const std::string& path, GbdtModel* model,
                     std::string* error) {
  std::ifstream file(path);
  if (!file) {
    *error = std::format("cannot open {}", path);
    return false;
  }
  std::stringstream contents;
  contents << file.rdbuf();
  if (!Parse(contents.str(), model, error)) {
    *error = std::format("{}: {}", path, *error);
    return false;
  }
  return true;
}

bool GbdtModel::Parse(const std::string& json, GbdtModel* model,
                      std::string* error) {
  const nlohmann::json root = nlohmann::json::parse(json, nullptr, false);
  if (!root.is_object() || root.value("format", "") != "bot-shield-gbdt") {
    *error = "not a bot-shield-gbdt model";
    return false;
  }
  if (root.value("feature_set", "") != kFeatureSetVersion) {
    *error = std::format("model is for feature set '{}', gateway has '{}'",
                         root.value("feature_set", ""), kFeatureSetVersion);
    return false;
  }
  const auto features = root.find("features");
  if (features == root.end() || !features->is_array() ||
      features->size() != kFeatureCount) {
    *error = "features do not match the gateway's feature set";
    return false;
  }
  for (std::size_t i = 0; i < kFeatureCount; ++i) {
    if (!(*features)[i].is_string() ||
        (*features)[i].get<std::string>() != kFeatureNames[i]) {
      *error = std::format("feature {} is not '{}'", i, kFeatureNames[i]);
      return false;
    }
  }
  const auto base = root.find("base");
  const auto trees = root.find("trees");
  if (base == root.end() || !base->is_number() || trees == root.end() ||
      !trees->is_array() || trees->size() > kMaxTrees) {
    *error = "expected base and trees";
    return false;
  }
  GbdtModel out;
  out.base_ = base->get<double>();
  for (std::size_t t = 0; t < trees->size(); ++t) {
    const nlohmann::json& node = (*trees)[t];
    Tree tree;
    if (!node.is_object() || !ReadArray(node, "value", 0, &tree.value) ||
        tree.value.empty() || tree.value.size() > kMaxNodes ||
        !ReadArray(node, "feature", tree.value.size(), &tree.feature) ||
        !ReadArray(node, "threshold", tree.value.size(), &tree.threshold) ||
        !ReadArray(node, "left", tree.value.size(), &tree.left) ||
        !ReadArray(node, "right", tree.value.size(), &tree.right)) {
      *error = std::format("tree {}: bad arrays", t);
      return false;
    }
    const auto size = static_cast<int32_t>(tree.value.size());
    for (int32_t i = 0; i < size; ++i) {
      if (tree.left[i] < 0) continue;  // Leaf.
      if (tree.feature[i] < 0 ||
          std::cmp_greater_equal(tree.feature[i], kFeatureCount) ||
          tree.left[i] <= i || tree.left[i] >= size || tree.right[i] <= i ||
          tree.right[i] >= size || !std::isfinite(tree.threshold[i])) {
        *error = std::format("tree {}: bad node {}", t, i);
        return false;
      }
    }
    out.trees_.push_back(std::move(tree));
  }
  *model = std::move(out);
  return true;
}

double GbdtModel::Predict(std::span<const float> features) const {
  double sum = base_;
  for (const Tree& tree : trees_) {
    std::size_t i = 0;
    while (tree.left[i] >= 0) {
      const auto feature = static_cast<std::size_t>(tree.feature[i]);
      const float x = feature < features.size() ? features[feature] : 0.0F;
      i = static_cast<std::size_t>(x < tree.threshold[i] ? tree.left[i]
                                                         : tree.right[i]);
    }
    sum += tree.value[i];
  }
  return 1.0 / (1.0 + std::exp(-sum));
}

}  // namespace bot_shield
