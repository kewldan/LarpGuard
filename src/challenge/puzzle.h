#ifndef BOT_SHIELD_CHALLENGE_PUZZLE_H_
#define BOT_SHIELD_CHALLENGE_PUZZLE_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {

// A small RGB raster with just what the CAPTCHA images need.
class Raster {
 public:
  struct Point {
    double x;
    double y;
  };
  struct Color {
    uint8_t r;
    uint8_t g;
    uint8_t b;
  };

  Raster(int width, int height, Color background);

  int width() const { return width_; }
  int height() const { return height_; }
  Color At(int x, int y) const;

  // Even-odd fill sampled at pixel centres.
  void FillPolygon(const std::vector<Point>& points, Color color, double alpha);
  void Line(Point from, Point to, double width, Color color, double alpha);
  // Adds uniform noise of +-`amount` to every channel.
  void Noise(int amount, uint64_t seed);
  // Box-filtered half size (the images are drawn at 2x for smoother edges).
  Raster Half() const;
  // 8-bit RGB PNG.
  std::string Png() const;

 private:
  void Blend(int x, int y, Color color, double alpha);

  int width_;
  int height_;
  std::vector<uint8_t> pixels_;
};

// One round of the built-in CAPTCHA: a 300x200 image with six blob shapes
// and a 100x100 sample of one of them, drawn rotated, scaled and recoloured.
// One distractor is a near twin of the target. The answer (target centre
// and radius in image pixels) never leaves the server unencrypted.
struct Puzzle {
  std::string image_png;
  std::string sample_png;
  int x = 0;
  int y = 0;
  int radius = 0;
};

Puzzle GeneratePuzzle(uint64_t seed);

// "data:image/png;base64,..." for an <img>.
std::string PngDataUri(std::string_view png);

}  // namespace bot_shield

#endif  // BOT_SHIELD_CHALLENGE_PUZZLE_H_
