// Number, time and text formatting used across screens.

const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

// 12480 → "12.5k", 9402 → "9,402", 4.2 → "4.2", 0.04 → "0.04".
export function compact(value: number): string {
  if (!Number.isFinite(value)) return '—';
  const abs = Math.abs(value);
  if (abs >= 1e9) return `${(value / 1e9).toFixed(1)}B`;
  if (abs >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
  if (abs >= 10_000) return `${(value / 1000).toFixed(1)}k`;
  if (abs >= 100 || Number.isInteger(value)) return integer.format(value);
  if (abs >= 1) return value.toFixed(1);
  if (abs === 0) return '0';
  return value.toFixed(2);
}

export function count(value: number): string {
  return integer.format(value);
}

export function percent(part: number, total: number, digits = 1): string {
  if (total <= 0) return '0%';
  return `${((part / total) * 100).toFixed(digits)}%`;
}

export function rate(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : compact(value);
}

const pad = (n: number) => String(n).padStart(2, '0');

// Local wall-clock time of a timestamp: "12:41:07".
export function clock(ms: number): string {
  const date = new Date(ms);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function dateTime(ms: number): string {
  const date = new Date(ms);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${clock(ms)}`;
}

// "now", "4 min ago", "3 h ago", "2 d ago".
export function ago(ms: number, now: number = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - ms) / 1000));
  if (seconds < 10) return 'now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86_400)} d ago`;
}

// 2537 → "42:17", 4000 → "1:06:40".
export function countdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rest = s % 60;
  return h > 0 ? `${h}:${pad(m)}:${pad(rest)}` : `${m}:${pad(rest)}`;
}

// 3_600_000 → "1h", 90_000 → "1.5m", 1000 → "1s".
export function duration(ms: number): string {
  if (ms % 86_400_000 === 0) return `${ms / 86_400_000}d`;
  if (ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
  if (ms % 60_000 === 0) return `${ms / 60_000}m`;
  if (ms % 1000 === 0) return `${ms / 1000}s`;
  return `${ms}ms`;
}

// Keeps the readable head and the end of a long fingerprint:
// "t13d1516h2_8daaf6152771_02713d6af862" → "t13d1516h2_8daa…f862".
export function shorten(value: string, head = 15, tail = 4): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

// Turns an offset (1-based column in the whole text) into line and column.
export function lineColumn(
  text: string,
  column: number,
): { line: number; col: number } {
  const before = text.slice(0, Math.max(0, column - 1));
  const lines = before.split('\n');
  return {
    line: lines.length,
    col: (lines[lines.length - 1]?.length ?? 0) + 1,
  };
}
