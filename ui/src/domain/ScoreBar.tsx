// Score 0–100 with ticks at the policy's thresholds; the fill takes the
// tone of the resulting action ("04 Score bar & reason chips").

import { scoreTone, type Tone } from '../design/tokens.ts';
import { TONE_TEXT as TEXT } from '../lib/tone.ts';

import type { Thresholds } from '../lib/tone.ts';

const FILL: Record<Tone, string> = {
  allowed: 'var(--color-allowed)',
  challenged: 'var(--color-challenged)',
  blocked: 'var(--color-blocked)',
};

// Table cell: the number and a 72 px bar.
export function ScoreCell({
  score,
  thresholds,
  width = 72,
}: {
  score: number;
  thresholds?: Thresholds;
  width?: number;
}) {
  const tone = scoreTone(score, thresholds);
  const clamped = Math.max(0, Math.min(100, score));
  const t = thresholds ?? { challenge: 40, block: 70 };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span
        className="mono"
        style={{
          width: 22,
          textAlign: 'right',
          fontSize: 12,
          color: TEXT[tone],
        }}
      >
        {score}
      </span>
      <span
        role="meter"
        aria-label="Score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        style={{
          position: 'relative',
          width,
          height: 6,
          borderRadius: 999,
          background: 'var(--color-surface-3)',
          flex: 'none',
        }}
      >
        <span
          style={{
            position: 'absolute',
            inset: '0 auto 0 0',
            width: `${clamped}%`,
            borderRadius: 999,
            background: FILL[tone],
          }}
        />
        {[t.challenge, t.block].map((tick) => (
          <span
            key={tick}
            style={{
              position: 'absolute',
              left: `${tick}%`,
              top: -2,
              width: 1,
              height: 10,
              background: 'var(--color-bg)',
            }}
          />
        ))}
      </span>
    </span>
  );
}

// The large bar of the detail panel: tinted zones and labelled ticks.
export function ScoreBar({
  score,
  thresholds = { challenge: 40, block: 70 },
  labels = ['challenge', 'block'],
}: {
  score: number;
  thresholds?: Thresholds;
  // What happens at each threshold (the policy's actions).
  labels?: [string, string];
}) {
  const tone = scoreTone(score, thresholds);
  const clamped = Math.max(0, Math.min(100, score));
  const ticks: [number, string][] = [
    [thresholds.challenge, `${thresholds.challenge} ${labels[0]}`],
    [thresholds.block, `${thresholds.block} ${labels[1]}`],
  ];
  return (
    <div style={{ position: 'relative', padding: '10px 0 30px' }}>
      <div
        role="meter"
        aria-label="Score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        style={{
          position: 'relative',
          height: 10,
          borderRadius: 999,
          background: 'var(--color-surface-3)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: `${thresholds.challenge}%`,
            width: `${thresholds.block - thresholds.challenge}%`,
            top: 0,
            bottom: 0,
            background: 'var(--color-challenged-soft)',
          }}
        />
        <div
          style={{
            position: 'absolute',
            left: `${thresholds.block}%`,
            right: 0,
            top: 0,
            bottom: 0,
            background: 'var(--color-blocked-soft)',
          }}
        />
        <div
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            width: `${clamped}%`,
            background: FILL[tone],
            borderRadius: 999,
            transition: 'width var(--duration-base) var(--ease-out)',
          }}
        />
      </div>
      {ticks.map(([at]) => (
        <div
          key={at}
          style={{
            position: 'absolute',
            left: `${at}%`,
            top: 4,
            width: 1,
            height: 22,
            background: 'var(--color-text-3)',
          }}
        />
      ))}
      <div
        className="mono"
        style={{
          position: 'absolute',
          left: 0,
          top: 34,
          fontSize: 11,
          color: 'var(--color-text-3)',
        }}
      >
        0
      </div>
      {ticks.map(([at, label]) => (
        <div
          key={label}
          className="mono"
          style={{
            position: 'absolute',
            left: `${at}%`,
            top: 34,
            transform: 'translateX(-50%)',
            fontSize: 11,
            color: 'var(--color-text-3)',
            whiteSpace: 'nowrap',
          }}
        >
          {label}
        </div>
      ))}
      <div
        className="mono"
        style={{
          position: 'absolute',
          right: 0,
          top: 34,
          fontSize: 11,
          color: 'var(--color-text-3)',
        }}
      >
        100
      </div>
    </div>
  );
}
