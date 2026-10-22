// Fingerprint pill (readable prefix and hash end, full on hover or focus in
// a layer above it so the table does not reflow, click to copy) and a segment-by-segment diff ("05 Fingerprint pill &
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
  const short = shorten(value);
  const pill = {
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
  } as const;
  return (
    <button
      type="button"
      className="mono"
      title="Click to copy"
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
        ...pill,
        position: 'relative',
        maxWidth: '100%',
        whiteSpace: 'nowrap',
      }}
    >
      <span>{short}</span>
      <Icon name="copy" size={12} strokeWidth={1.1} />
      {open && short !== value ? (
        <span
          aria-hidden="true"
          style={{
            ...pill,
            position: 'absolute',
            top: -1,
            left: -1,
            zIndex: 2,
            width: 'max-content',
            maxWidth: 'min(640px, 80vw)',
            whiteSpace: 'normal',
            overflowWrap: 'anywhere',
            border: '1px solid var(--color-text-3)',
            boxShadow: 'var(--shadow-overlay)',
            pointerEvents: 'none',
          }}
        >
          <span>{value}</span>
          <Icon name="copy" size={12} strokeWidth={1.1} />
        </span>
      ) : null}
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
