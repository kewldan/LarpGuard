#ifndef BOT_SHIELD_MODEL_GBDT_H_
#define BOT_SHIELD_MODEL_GBDT_H_

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace bot_shield {

// Gradient-boosted trees for the model signal, trained offline by
// tools/train_model.py. JSON:
//   {"format": "bot-shield-gbdt", "feature_set": "f1",
//    "features": [names, as kFeatureNames], "base": <log-odds>,
//    "trees": [{"feature": [...], "threshold": [...], "left": [...],
//               "right": [...], "value": [...]}, ...]}
// Node i is a leaf when left[i] < 0 (value[i] is added); otherwise the
// walk goes left when x[feature[i]] < threshold[i]. Children come after
// their parent, so a walk always ends.
class GbdtModel {
 public:
  static bool Load(const std::string& path, GbdtModel* model,
                   std::string* error);
  static bool Parse(const std::string& json, GbdtModel* model,
                    std::string* error);

  // Probability that the request is automated, 0..1.
  double Predict(std::span<const float> features) const;
  std::size_t tree_count() const { return trees_.size(); }

 private:
  struct Tree {
    std::vector<int32_t> feature;
    std::vector<float> threshold;
    std::vector<int32_t> left;
    std::vector<int32_t> right;
    std::vector<float> value;
  };
  double base_ = 0;
  std::vector<Tree> trees_;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_MODEL_GBDT_H_
