// Diffs: fingerprint segments and lines of JSON state.

export interface DiffToken {
  text: string;
  changed: boolean;
}

// Splits both values on `separator` and marks the segments of `value` that
// differ from `base` at the same position.
export function diffSegments(
  value: string,
  base: string,
  separator: string,
): DiffToken[] {
  const ours = value.split(separator);
  const theirs = base.split(separator);
  return ours.map((part, i) => ({
    text: part + (i < ours.length - 1 ? separator : ''),
    changed: theirs[i] !== part,
  }));
}

export function separatorFor(kind: string): string {
  if (kind === 'h2_fp') return '|';
  if (kind === 'tcp_fp') return ':';
  return '_';
}

export interface DiffLine {
  mark: ' ' | '+' | '-';
  text: string;
}

// Line diff by longest common subsequence (states are small JSON).
export function diffLines(before: string[], after: string[]): DiffLine[] {
  const n = before.length;
  const m = after.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () =>
    new Array<number>(m + 1).fill(0),
  );
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      const row = lcs[i] as number[];
      row[j] =
        before[i] === after[j]
          ? (lcs[i + 1]?.[j + 1] ?? 0) + 1
          : Math.max(lcs[i + 1]?.[j] ?? 0, row[j + 1] ?? 0);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && before[i] === after[j]) {
      out.push({ mark: ' ', text: before[i] ?? '' });
      i += 1;
      j += 1;
    } else if (
      j < m &&
      (i >= n || (lcs[i]?.[j + 1] ?? 0) >= (lcs[i + 1]?.[j] ?? 0))
    ) {
      out.push({ mark: '+', text: after[j] ?? '' });
      j += 1;
    } else {
      out.push({ mark: '-', text: before[i] ?? '' });
      i += 1;
    }
  }
  return out;
}
