#include "challenge/puzzle.h"

#include <openssl/base64.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <numbers>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "common/compress.h"

namespace bot_shield {
namespace {

using Point = Raster::Point;
using Color = Raster::Color;

// A star-shaped blob: vertex radii (0..1) at evenly spaced angles with
// jitter; drawn at any rotation and scale.
struct Shape {
  std::vector<double> radii;
  std::vector<double> jitter;  // Angle offsets, fractions of a step.
};

Shape RandomShape(std::mt19937_64& rng) {
  std::uniform_int_distribution<int> vertices(6, 9);
  std::uniform_real_distribution<double> radius(0.55, 1.0);
  std::uniform_real_distribution<double> notch(0.22, 0.4);
  std::uniform_real_distribution<double> jitter(-0.2, 0.2);
  Shape shape;
  const int n = vertices(rng);
  for (int i = 0; i < n; ++i) {
    shape.radii.push_back(radius(rng));
    shape.jitter.push_back(jitter(rng));
  }
  // Two or three deep notches at random places: concave silhouettes that
  // people tell apart at a glance, whatever the rotation.
  const int notches = 2 + static_cast<int>(rng() % 2);
  for (int k = 0; k < notches; ++k) {
    shape.radii[static_cast<std::size_t>(rng() % shape.radii.size())] =
        notch(rng);
  }
  return shape;
}

// Same vertex count, two vertices clearly moved: looks alike at a glance.
Shape NearTwin(const Shape& shape, std::mt19937_64& rng) {
  Shape twin = shape;
  std::uniform_real_distribution<double> change(0.35, 0.5);
  for (int k = 0; k < 2; ++k) {
    double& r = twin.radii[static_cast<std::size_t>(rng() % twin.radii.size())];
    r = r > 0.6 ? r - change(rng) : r + change(rng);
  }
  return twin;
}

std::vector<Point> Outline(const Shape& shape, Point centre, double scale,
                           double rotation) {
  std::vector<Point> points;
  const double step =
      2 * std::numbers::pi / static_cast<double>(shape.radii.size());
  for (std::size_t i = 0; i < shape.radii.size(); ++i) {
    const double angle =
        rotation + step * (static_cast<double>(i) + shape.jitter[i]);
    points.push_back({centre.x + std::cos(angle) * shape.radii[i] * scale,
                      centre.y + std::sin(angle) * shape.radii[i] * scale});
  }
  return points;
}

Color Hsv(double hue, double saturation, double value) {
  const double c = value * saturation;
  const double h = std::fmod(hue, 360.0) / 60.0;
  const double x = c * (1 - std::fabs(std::fmod(h, 2.0) - 1));
  double r = 0;
  double g = 0;
  double b = 0;
  if (h < 1) {
    r = c, g = x;
  } else if (h < 2) {
    r = x, g = c;
  } else if (h < 3) {
    g = c, b = x;
  } else if (h < 4) {
    g = x, b = c;
  } else if (h < 5) {
    r = x, b = c;
  } else {
    r = c, b = x;
  }
  const double m = value - c;
  const auto to8 = [m](double v) {
    return static_cast<uint8_t>(std::clamp((v + m) * 255.0, 0.0, 255.0));
  };
  return {to8(r), to8(g), to8(b)};
}

void DrawShape(Raster* raster, const Shape& shape, Point centre, double scale,
               double rotation, Color fill) {
  const std::vector<Point> points = Outline(shape, centre, scale, rotation);
  raster->FillPolygon(points, fill, 0.9);
  const Color edge{static_cast<uint8_t>(fill.r / 2),
                   static_cast<uint8_t>(fill.g / 2),
                   static_cast<uint8_t>(fill.b / 2)};
  for (std::size_t i = 0; i < points.size(); ++i) {
    raster->Line(points[i], points[(i + 1) % points.size()], 3.0, edge, 0.9);
  }
}

// Faint curves and specks: no clean background to segment against.
void Clutter(Raster* raster, std::mt19937_64& rng, int curves, double alpha) {
  std::uniform_real_distribution<double> x(0, raster->width());
  std::uniform_real_distribution<double> y(0, raster->height());
  std::uniform_real_distribution<double> hue(0, 360);
  std::uniform_real_distribution<double> step(-60, 60);
  std::uniform_real_distribution<double> width(1.5, 4.0);
  for (int i = 0; i < curves; ++i) {
    Point p{x(rng), y(rng)};
    const Color color = Hsv(hue(rng), 0.5, 0.75);
    const double w = width(rng);
    for (int segment = 0; segment < 5; ++segment) {
      const Point next{p.x + step(rng), p.y + step(rng)};
      raster->Line(p, next, w, color, alpha);
      p = next;
    }
  }
}

void Chunk(std::string* out, std::string_view type, std::string_view data) {
  const auto u32 = [out](uint32_t v) {
    out->push_back(static_cast<char>(v >> 24));
    out->push_back(static_cast<char>((v >> 16) & 0xFF));
    out->push_back(static_cast<char>((v >> 8) & 0xFF));
    out->push_back(static_cast<char>(v & 0xFF));
  };
  u32(static_cast<uint32_t>(data.size()));
  const std::string body = std::string(type) + std::string(data);
  out->append(body);
  u32(Crc32(body));
}

}  // namespace

Raster::Raster(int width, int height, Color background)
    : width_(width),
      height_(height),
      pixels_(static_cast<std::size_t>(width) * height * 3) {
  for (std::size_t i = 0; i < pixels_.size(); i += 3) {
    pixels_[i] = background.r;
    pixels_[i + 1] = background.g;
    pixels_[i + 2] = background.b;
  }
}

Raster::Color Raster::At(int x, int y) const {
  const auto i = (static_cast<std::size_t>(y) * width_ + x) * 3;
  return {pixels_[i], pixels_[i + 1], pixels_[i + 2]};
}

void Raster::Blend(int x, int y, Color color, double alpha) {
  if (x < 0 || y < 0 || x >= width_ || y >= height_) return;
  const auto i = (static_cast<std::size_t>(y) * width_ + x) * 3;
  const auto mix = [alpha](uint8_t under, uint8_t over) {
    return static_cast<uint8_t>(
        std::lround(under * (1 - alpha) + over * alpha));
  };
  pixels_[i] = mix(pixels_[i], color.r);
  pixels_[i + 1] = mix(pixels_[i + 1], color.g);
  pixels_[i + 2] = mix(pixels_[i + 2], color.b);
}

void Raster::FillPolygon(const std::vector<Point>& points, Color color,
                         double alpha) {
  if (points.size() < 3) return;
  double top = points[0].y;
  double bottom = points[0].y;
  for (const Point& p : points) {
    top = std::min(top, p.y);
    bottom = std::max(bottom, p.y);
  }
  const int first = std::max(0, static_cast<int>(std::floor(top)));
  const int last = std::min(height_ - 1, static_cast<int>(std::ceil(bottom)));
  std::vector<double> crossings;
  for (int y = first; y <= last; ++y) {
    const double cy = y + 0.5;
    crossings.clear();
    for (std::size_t i = 0; i < points.size(); ++i) {
      const Point& a = points[i];
      const Point& b = points[(i + 1) % points.size()];
      if ((a.y <= cy && b.y > cy) || (b.y <= cy && a.y > cy)) {
        crossings.push_back(a.x + (cy - a.y) * (b.x - a.x) / (b.y - a.y));
      }
    }
    std::ranges::sort(crossings);
    for (std::size_t i = 0; i + 1 < crossings.size(); i += 2) {
      const int from =
          std::max(0, static_cast<int>(std::ceil(crossings[i] - 0.5)));
      const int to = std::min(
          width_ - 1, static_cast<int>(std::floor(crossings[i + 1] - 0.5)));
      for (int x = from; x <= to; ++x) Blend(x, y, color, alpha);
    }
  }
}

void Raster::Line(Point from, Point to, double width, Color color,
                  double alpha) {
  const double dx = to.x - from.x;
  const double dy = to.y - from.y;
  const double length = std::hypot(dx, dy);
  if (length < 1e-6) return;
  const double nx = -dy / length * width / 2;
  const double ny = dx / length * width / 2;
  FillPolygon({{from.x + nx, from.y + ny},
               {to.x + nx, to.y + ny},
               {to.x - nx, to.y - ny},
               {from.x - nx, from.y - ny}},
              color, alpha);
}

void Raster::Noise(int amount, uint64_t seed) {
  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<int> delta(-amount, amount);
  for (uint8_t& channel : pixels_) {
    channel = static_cast<uint8_t>(std::clamp(channel + delta(rng), 0, 255));
  }
}

Raster Raster::Half() const {
  Raster out(width_ / 2, height_ / 2, {0, 0, 0});
  for (int y = 0; y < out.height_; ++y) {
    for (int x = 0; x < out.width_; ++x) {
      for (int c = 0; c < 3; ++c) {
        int sum = 0;
        for (int sy = 0; sy < 2; ++sy) {
          for (int sx = 0; sx < 2; ++sx) {
            sum += pixels_[(static_cast<std::size_t>(y * 2 + sy) * width_ +
                            (x * 2 + sx)) *
                               3 +
                           c];
          }
        }
        out.pixels_[(static_cast<std::size_t>(y) * out.width_ + x) * 3 + c] =
            static_cast<uint8_t>((sum + 2) / 4);
      }
    }
  }
  return out;
}

std::string Raster::Png() const {
  std::string rows;
  rows.reserve(pixels_.size() + height_);
  for (int y = 0; y < height_; ++y) {
    rows.push_back('\0');  // Filter: none.
    rows.append(reinterpret_cast<const char*>(pixels_.data()) +
                    static_cast<std::size_t>(y) * width_ * 3,
                static_cast<std::size_t>(width_) * 3);
  }
  std::string png("\x89PNG\r\n\x1a\n", 8);
  std::string header;
  for (const uint32_t v :
       {static_cast<uint32_t>(width_), static_cast<uint32_t>(height_)}) {
    header.push_back(static_cast<char>(v >> 24));
    header.push_back(static_cast<char>((v >> 16) & 0xFF));
    header.push_back(static_cast<char>((v >> 8) & 0xFF));
    header.push_back(static_cast<char>(v & 0xFF));
  }
  header += std::string("\x08\x02\x00\x00\x00", 5);  // 8-bit RGB.
  Chunk(&png, "IHDR", header);
  Chunk(&png, "IDAT", ZlibCompress(rows));
  Chunk(&png, "IEND", "");
  return png;
}

Puzzle GeneratePuzzle(uint64_t seed) {
  std::mt19937_64 rng(seed);
  std::uniform_real_distribution<double> unit(0, 1);
  std::uniform_real_distribution<double> hue(0, 360);
  std::uniform_real_distribution<double> angle(0, 2 * std::numbers::pi);
  std::uniform_real_distribution<double> offset(-22, 22);
  std::uniform_real_distribution<double> scale(52, 64);

  // Drawn at 600x400, delivered at 300x200.
  const double base_hue = hue(rng);
  Raster image(600, 400, Hsv(base_hue, 0.08, 0.96));
  Clutter(&image, rng, 46, 0.35);

  const Shape target = RandomShape(rng);
  std::vector<Shape> shapes = {target, NearTwin(target, rng)};
  while (shapes.size() < 6) shapes.push_back(RandomShape(rng));
  std::array<int, 6> order = {0, 1, 2, 3, 4, 5};
  std::ranges::shuffle(order, rng);

  Puzzle puzzle;
  for (std::size_t cell = 0; cell < 6; ++cell) {
    const Point centre{
        100.0 + 200.0 * static_cast<double>(cell % 3) + offset(rng),
        (cell < 3 ? 100.0 : 300.0) + offset(rng)};
    const double size = scale(rng);
    const int index = order[cell];
    DrawShape(&image, shapes[static_cast<std::size_t>(index)], centre, size,
              angle(rng), Hsv(hue(rng), 0.55 + 0.3 * unit(rng), 0.85));
    if (index == 0) {
      puzzle.x = static_cast<int>(std::lround(centre.x / 2));
      puzzle.y = static_cast<int>(std::lround(centre.y / 2));
      puzzle.radius = static_cast<int>(std::lround(size / 2));
    }
  }
  Clutter(&image, rng, 9, 0.45);
  image.Noise(4, rng());
  puzzle.image_png = image.Half().Png();

  Raster sample(200, 200, Hsv(base_hue + 180, 0.06, 0.97));
  Clutter(&sample, rng, 10, 0.25);
  DrawShape(&sample, target, {100 + offset(rng) / 3, 100 + offset(rng) / 3}, 74,
            angle(rng), Hsv(hue(rng), 0.6, 0.8));
  sample.Noise(4, rng());
  puzzle.sample_png = sample.Half().Png();
  return puzzle;
}

std::string PngDataUri(std::string_view png) {
  std::size_t size = 0;
  EVP_EncodedLength(&size, png.size());
  std::string encoded(size, '\0');
  encoded.resize(EVP_EncodeBlock(reinterpret_cast<uint8_t*>(encoded.data()),
                                 reinterpret_cast<const uint8_t*>(png.data()),
                                 png.size()));
  return "data:image/png;base64," + encoded;
}

}  // namespace bot_shield
