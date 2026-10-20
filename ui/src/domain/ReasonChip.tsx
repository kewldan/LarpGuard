import { weightColor } from '../lib/signals.ts';

// A signal with its weight: name | +32. Blocking weights (25 and up) are
// orange, smaller ones amber, negative ones (trust) blue.

function borderColor(weight: number | null): string {
  if (weight === null) return 'var(--color-line-strong)';
  if (weight < 0) return 'var(--color-verified)';
  return weight >= 25 ? 'var(--color-blocked)' : 'var(--color-challenged)';
}

export function ReasonChip({
  reason,
  weight,
}: {
  reason: string;
  weight: number | null;
}) {
  return (
    <span
      className="mono"
      style={{
        display: 'inline-flex',
        alignItems: 'stretch',
        height: 26,
        borderRadius: 6,
        fontSize: 12,
        overflow: 'hidden',
        border: `1px solid ${borderColor(weight)}`,
        background: 'var(--color-surface-2)',
        maxWidth: '100%',
      }}
    >
      <span
        style={{
          padding: '0 8px',
          display: 'inline-flex',
          alignItems: 'center',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {reason}
      </span>
      {weight !== null ? (
        <span
          style={{
            padding: '0 8px',
            display: 'inline-flex',
            alignItems: 'center',
            borderLeft: `1px solid ${borderColor(weight)}`,
            color: weightColor(weight),
            fontWeight: 600,
          }}
        >
          {weight < 0 ? `−${Math.abs(weight)}` : `+${weight}`}
        </span>
      ) : null}
    </span>
  );
}
