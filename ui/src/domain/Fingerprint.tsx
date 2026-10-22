// Fingerprint pill (readable prefix and hash end, full on hover or focus,
// click to copy) and a segment-by-segment diff ("05 Fingerprint pill &
// diff").

import { useState } from 'react';

import type { DiffToken } from '../lib/diff.ts';
import { shorten } from '../lib/format.ts';
import { Icon } from '../ui/Icon.tsx';
import { useCopy } from '../ui/toast-context.ts';

export function FingerprintPill({
  value,
  kind,
}: {
  value: string;
  kind?: string;
}) {
  const copy = useCopy();
  const [open, setOpen] = useState(false);
  if (!value) return <span style={{ color: 'var(--color-text-3)' }}>—</span>;
  return (
    <button
      type="button"
      className="mono"
      title={`${value} (click to copy)`}
      aria-label={`Copy ${kind ?? 'fingerprint'} ${value}`}
      onMouseEnter={() => {
        setOpen(true);
      }}
      onMouseLeave={() => {
        setOpen(false);
      }}
      onFocus={() => {
        setOpen(true);
      }}
      onBlur={() => {
        setOpen(false);
      }}
      onClick={(event) => {
        event.stopPropagation();
        copy(value, kind);
      }}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        minHeight: 26,
        padding: '2px 10px',
        borderRadius: 6,
        border: '1px solid var(--color-line-strong)',
        background: 'var(--color-surface-2)',
        fontSize: 12,
        textAlign: 'left',
        maxWidth: '100%',
        overflowWrap: 'anywhere',
      }}
    >
      <span>{open ? value : shorten(value)}</span>
      <Icon name="copy" size={12} strokeWidth={1.1} />
    </button>
  );
}

export function DiffLine({
  tokens,
  highlight,
}: {
  tokens: DiffToken[];
  highlight: boolean;
}) {
  return (
    <span
      className="mono"
      style={{ fontSize: 12.5, lineHeight: 1.7, overflowWrap: 'anywhere' }}
    >
      {tokens.map((token, i) => (
        <span
          // biome-ignore lint/suspicious/noArrayIndexKey: tokens are positional and never reorder.
          key={i}
          style={{
            padding: '1px 2px',
            borderRadius: 3,
            background:
              highlight && token.changed
                ? 'var(--color-blocked-soft)'
                : 'transparent',
            color: !highlight
              ? 'var(--color-text)'
              : token.changed
                ? 'var(--color-blocked-text)'
                : 'var(--color-text-2)',
          }}
        >
          {token.text}
        </span>
      ))}
    </span>
  );
}
