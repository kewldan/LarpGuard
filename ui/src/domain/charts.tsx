// The console's charts, drawn as plain SVG from the design: sparklines,
// the stacked verdict area with the dashed would-block line, health dots.

import { useMemo, useState, type ReactNode } from 'react';

import type { VerdictPoint } from '../../shared/api.ts';
import { niceCeil, sparkPoints } from '../lib/chart-math.ts';
import { clock, compact } from '../lib/format.ts';

export function Sparkline({
  values,
  width = 72,
  height = 20,
  color = 'var(--color-text-3)',
  max,
  fluid = false,
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  max?: number;
  fluid?: boolean;
}) {
  return (
    <svg
      width={fluid ? '100%' : width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      aria-hidden="true"
      style={{ display: 'block', flex: 'none' }}
    >
      <polyline
        points={sparkPoints(values, width, height, max)}
        fill="none"
        stroke={color}
        strokeWidth="1.3"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

const WIDTH = 1000;

function area(
  lower: number[],
  upper: number[],
  y: (v: number) => number,
): string {
  const n = upper.length;
  if (n === 0) return '';
  const x = (i: number) => (n > 1 ? (i / (n - 1)) * WIDTH : 0);
  let d = `M${x(0)},${y(upper[0] ?? 0).toFixed(1)}`;
  for (let i = 1; i < n; i += 1)
    d += ` L${x(i).toFixed(1)},${y(upper[i] ?? 0).toFixed(1)}`;
  for (let i = n - 1; i >= 0; i -= 1)
    d += ` L${x(i).toFixed(1)},${y(lower[i] ?? 0).toFixed(1)}`;
  return `${d} Z`;
}

// "Verdicts over time": allowed, challenged and blocked stacked, the
// would-block line on top (shadow hosts).
export function VerdictChart({
  series,
  height = 220,
  axis = true,
  tooltip = true,
}: {
  series: VerdictPoint[];
  height?: number;
  axis?: boolean;
  tooltip?: boolean;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const shape = useMemo(() => {
    const allowed = series.map((p) => p.allowed);
    const challenged = series.map((p, i) => (allowed[i] ?? 0) + p.challenged);
    const total = series.map((p, i) => (challenged[i] ?? 0) + p.blocked);
    const would = series.map((p, i) => (total[i] ?? 0) + p.would_block);
    const peak = Math.max(...would, 0);
    const max = peak > 0 ? niceCeil(peak * 1.08) : 1;
    const y = (v: number) => height - (v / max) * height;
    const zero = series.map(() => 0);
    const n = series.length;
    return {
      max,
      allowedPath: area(zero, allowed, y),
      challengedPath: area(allowed, challenged, y),
      blockedPath: area(challenged, total, y),
      wouldLine: would
        .map(
          (v, i) =>
            `${(n > 1 ? (i / (n - 1)) * WIDTH : 0).toFixed(1)},${y(v).toFixed(1)}`,
        )
        .join(' '),
      hasWould: series.some((p) => p.would_block > 0),
    };
  }, [series, height]);
  const n = series.length;
  const point = hover !== null ? series[hover] : undefined;
  const label = `Stacked area of allowed, challenged and blocked requests per second, peak ${compact(shape.max)}`;
  return (
    <div style={{ display: 'flex', gap: 8 }}>
      {axis ? (
        <div
          className="mono"
          aria-hidden="true"
          style={{
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            fontSize: 10.5,
            color: 'var(--color-text-3)',
            textAlign: 'right',
            height,
            minWidth: 28,
          }}
        >
          <span>{compact(shape.max)}</span>
          <span>{compact(shape.max / 2)}</span>
          <span>0</span>
        </div>
      ) : null}
      <div style={{ position: 'relative', flex: 1, minWidth: 0, height }}>
        <svg
          width="100%"
          height={height}
          viewBox={`0 0 ${WIDTH} ${height}`}
          preserveAspectRatio="none"
          role="img"
          aria-label={label}
          style={{ display: 'block' }}
        >
          {axis ? (
            <>
              <line
                x1="0"
                y1="0.5"
                x2={WIDTH}
                y2="0.5"
                stroke="var(--color-line)"
                vectorEffect="non-scaling-stroke"
              />
              <line
                x1="0"
                y1={height / 2}
                x2={WIDTH}
                y2={height / 2}
                stroke="var(--color-line)"
                vectorEffect="non-scaling-stroke"
              />
              <line
                x1="0"
                y1={height - 0.5}
                x2={WIDTH}
                y2={height - 0.5}
                stroke="var(--color-line-strong)"
                vectorEffect="non-scaling-stroke"
              />
            </>
          ) : null}
          <path
            className="morph"
            d={shape.allowedPath}
            fill="var(--color-allowed-chart)"
          />
          <path
            className="morph"
            d={shape.challengedPath}
            fill="var(--color-challenged)"
          />
          <path
            className="morph"
            d={shape.blockedPath}
            fill="var(--color-blocked)"
          />
          {shape.hasWould ? (
            <polyline
              points={shape.wouldLine}
              fill="none"
              stroke="var(--color-text)"
              strokeWidth="1.5"
              strokeDasharray="5 4"
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
          {hover !== null && n > 1 ? (
            <line
              x1={(hover / (n - 1)) * WIDTH}
              x2={(hover / (n - 1)) * WIDTH}
              y1="0"
              y2={height}
              stroke="var(--color-text)"
              strokeWidth="1"
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
        </svg>
        {tooltip ? (
          <div
            style={{ position: 'absolute', inset: 0, display: 'flex' }}
            onMouseLeave={() => {
              setHover(null);
            }}
          >
            {series.map((p, i) => (
              <div
                key={p.t}
                style={{ flex: 1, height: '100%' }}
                onMouseEnter={() => {
                  setHover(i);
                }}
              />
            ))}
          </div>
        ) : null}
        {point && hover !== null ? (
          <div
            role="tooltip"
            style={{
              position: 'absolute',
              top: 8,
              left: `${n > 1 ? (hover / (n - 1)) * 100 : 0}%`,
              transform: `translateX(${hover > n / 2 ? 'calc(-100% - 12px)' : '12px'})`,
              pointerEvents: 'none',
              minWidth: 180,
              border: '1px solid var(--color-line-strong)',
              borderRadius: 10,
              background: 'var(--color-bg)',
              padding: '10px 12px',
              fontSize: 12,
              boxShadow: 'var(--shadow-tooltip)',
              animation: 'fade 120ms var(--ease-out) both',
            }}
          >
            <div
              className="mono"
              style={{ color: 'var(--color-text-3)', marginBottom: 6 }}
            >
              {clock(point.t)} · per second
            </div>
            <TipRow label="Allowed" value={point.allowed} />
            <TipRow
              label="Challenged"
              value={point.challenged}
              color="var(--color-challenged-text)"
            />
            <TipRow
              label="Blocked"
              value={point.blocked}
              color="var(--color-blocked-text)"
            />
            <div
              style={{
                borderTop: '1px dashed var(--color-line-strong)',
                marginTop: 6,
                paddingTop: 6,
              }}
            >
              <TipRow
                label="Would block"
                value={point.would_block}
                color="var(--color-text-2)"
              />
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function TipRow({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        gap: 16,
        color,
      }}
    >
      <span>{label}</span>
      <span className="mono">{compact(value)}</span>
    </div>
  );
}

export function Legend() {
  const swatch = (color: string) => (
    <span
      style={{ width: 10, height: 10, borderRadius: 2, background: color }}
    />
  );
  const item = (node: ReactNode, text: string) => (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      {node}
      {text}
    </span>
  );
  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '6px 14px',
        fontSize: 12,
        color: 'var(--color-text-2)',
      }}
    >
      {item(swatch('var(--color-allowed-chart)'), 'Allowed')}
      {item(swatch('var(--color-challenged)'), 'Challenged')}
      {item(swatch('var(--color-blocked)'), 'Blocked')}
      {item(
        <span
          style={{
            width: 14,
            height: 0,
            borderTop: '1.5px dashed var(--color-text)',
          }}
        />,
        'Would block (shadow)',
      )}
    </div>
  );
}

export type HealthState = 'ok' | 'degraded' | 'down' | 'off';

// Health uses teal only, so it never competes with verdict colors.
export function HealthDot({
  state,
  size = 8,
}: {
  state: HealthState;
  size?: number;
}) {
  const look: Record<HealthState, [string, string]> = {
    ok: ['var(--color-healthy)', 'var(--color-healthy-soft)'],
    degraded: ['var(--color-challenged)', 'var(--color-challenged-soft)'],
    down: ['var(--color-text)', 'var(--color-surface-3)'],
    off: ['var(--color-text-3)', 'var(--color-surface-3)'],
  };
  const [dot, ring] = look[state];
  return (
    <span
      aria-hidden="true"
      style={{
        flex: 'none',
        width: size,
        height: size,
        borderRadius: 999,
        background: dot,
        boxShadow: `0 0 0 3px ${ring}`,
      }}
    />
  );
}
