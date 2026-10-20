// Chart arithmetic: polyline points and round axis maxima.

export function sparkPoints(
  values: number[],
  width: number,
  height: number,
  max?: number,
): string {
  if (values.length === 0) return '';
  const top = max ?? Math.max(...values, 0);
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  return values
    .map((value, i) => {
      const y = height - 1 - (top > 0 ? (value / top) * (height - 2) : 0);
      return `${(i * step).toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

// 1, 2, 5 × 10^n at or above `value`.
export function niceCeil(value: number): number {
  if (value <= 0) return 1;
  const power = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (step * power >= value) return step * power;
  }
  return 10 * power;
}
