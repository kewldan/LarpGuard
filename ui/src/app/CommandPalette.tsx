// ⌘K: jump to an IP hash or network, a JA4, a host, an AS or a rule. The
// kind of item follows from what is typed (the BFF decides); screens match
// by name.

import { useNavigate } from '@tanstack/react-router';
import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';

import type { SearchResult } from '../../shared/api.ts';
import { useSearch } from '../lib/queries.ts';
import { Kbd } from '../ui/controls.tsx';
import { Icon } from '../ui/Icon.tsx';
import { NAV } from './nav.ts';

interface Item {
  kind: string;
  value: string;
  meta: string;
  go: () => void;
}

export function CommandPalette({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const deferred = useDeferredValue(q.trim());
  const search = useSearch(deferred);
  const navigate = useNavigate();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      setQ('');
      setActive(0);
      dialog.showModal();
    }
    if (!open && dialog.open) dialog.close();
  }, [open]);

  const items = useMemo<Item[]>(() => {
    const go = (fn: () => Promise<void>) => () => {
      onClose();
      void fn();
    };
    const fromResult = (result: SearchResult): Item | null => {
      switch (result.kind) {
        case 'host':
          return {
            ...result,
            go: go(() =>
              navigate({ to: '/requests', search: { host: result.value } }),
            ),
          };
        case 'rule':
          return {
            ...result,
            go: go(() =>
              navigate({ to: '/rules', search: { rule: result.value } }),
            ),
          };
        case 'ja4':
          return {
            ...result,
            go: go(() =>
              navigate({ to: '/requests', search: { ja4: result.value } }),
            ),
          };
        case 'asn':
          return {
            ...result,
            go: go(() =>
              navigate({
                to: '/requests',
                search: { asn: Number(result.value.slice(2)) },
              }),
            ),
          };
        case 'ip':
          return result.value.startsWith('h:')
            ? {
                ...result,
                go: go(() =>
                  navigate({
                    to: '/requests',
                    search: { ip_hash: result.value.slice(2) },
                  }),
                ),
              }
            : {
                ...result,
                go: go(() =>
                  navigate({
                    to: '/requests',
                    search: { ip_prefix: result.value },
                  }),
                ),
              };
        case 'request':
          return null;
      }
    };
    const needle = q.trim().toLowerCase();
    const screens: Item[] = NAV.filter(
      (item) => needle === '' || item.name.toLowerCase().includes(needle),
    ).map((item) => ({
      kind: 'screen',
      value: item.name,
      meta: '',
      go: go(() => navigate({ to: item.to })),
    }));
    const results = (needle ? (search.data?.results ?? []) : [])
      .map(fromResult)
      .filter((item): item is Item => item !== null);
    return [...results, ...screens].slice(0, 12);
  }, [q, search.data, navigate, onClose]);

  const index = Math.min(active, Math.max(0, items.length - 1));

  return (
    // biome-ignore lint/a11y/useKeyWithClickEvents: backdrop clicks only; Escape closes the dialog natively.
    <dialog
      ref={ref}
      aria-label="Command palette"
      onClose={onClose}
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
      style={{
        margin: '72px auto auto',
        width: 'min(560px, calc(100vw - 32px))',
        padding: 0,
        border: '1px solid var(--color-line-strong)',
        borderRadius: 'var(--radius-overlay)',
        background: 'var(--color-surface-1)',
        color: 'var(--color-text)',
        boxShadow: 'var(--shadow-overlay)',
        overflow: 'hidden',
        animation: 'rise var(--duration-fast) var(--ease-out) both',
      }}
    >
      {open ? (
        <>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '0 14px',
              height: 48,
              borderBottom: '1px solid var(--color-line)',
              color: 'var(--color-text-3)',
            }}
          >
            <Icon name="search" size={14} strokeWidth={1.4} />
            <input
              autoFocus
              aria-label="Search"
              role="combobox"
              aria-expanded="true"
              aria-controls="palette-results"
              aria-activedescendant={
                items[index] ? `palette-${index}` : undefined
              }
              className="mono"
              placeholder="Type a /24, AS number, JA4, host or rule"
              value={q}
              onChange={(event) => {
                setQ(event.target.value);
                setActive(0);
              }}
              onKeyDown={(event) => {
                if (event.key === 'ArrowDown') {
                  event.preventDefault();
                  setActive((i) => Math.min(i + 1, items.length - 1));
                } else if (event.key === 'ArrowUp') {
                  event.preventDefault();
                  setActive((i) => Math.max(i - 1, 0));
                } else if (event.key === 'Enter') {
                  event.preventDefault();
                  items[index]?.go();
                }
              }}
              style={{
                flex: 1,
                minWidth: 0,
                border: 0,
                background: 'transparent',
                fontSize: 13,
                color: 'var(--color-text)',
              }}
            />
            <Kbd>esc</Kbd>
          </div>
          <div
            id="palette-results"
            role="listbox"
            style={{ padding: 6, maxHeight: 340, overflow: 'auto' }}
          >
            {items.map((item, i) => (
              <button
                key={`${item.kind}:${item.value}`}
                id={`palette-${i}`}
                type="button"
                role="option"
                aria-selected={i === index}
                onMouseEnter={() => {
                  setActive(i);
                }}
                onClick={item.go}
                style={{
                  display: 'flex',
                  width: '100%',
                  alignItems: 'center',
                  gap: 10,
                  height: 36,
                  padding: '0 10px',
                  border: 0,
                  borderRadius: 8,
                  background:
                    i === index ? 'var(--color-surface-3)' : 'transparent',
                  textAlign: 'left',
                  animation: `rise var(--duration-base) var(--ease-out) ${i * 18}ms both`,
                }}
              >
                <span
                  style={{
                    width: 52,
                    fontSize: 10.5,
                    letterSpacing: '0.06em',
                    color: 'var(--color-text-3)',
                    textTransform: 'uppercase',
                  }}
                >
                  {item.kind}
                </span>
                <span
                  className="mono"
                  style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 12.5,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {item.value}
                </span>
                <span style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                  {item.meta}
                </span>
              </button>
            ))}
            {items.length === 0 ? (
              <div
                style={{
                  padding: '14px 10px',
                  fontSize: 13,
                  color: 'var(--color-text-3)',
                }}
              >
                No match. Try a /24, an AS number like AS64496, or a JA4 prefix.
              </div>
            ) : null}
          </div>
          <div
            style={{
              display: 'flex',
              gap: 14,
              padding: '8px 14px',
              borderTop: '1px solid var(--color-line)',
              fontSize: 11,
              color: 'var(--color-text-3)',
            }}
          >
            <span>
              <span className="mono">↑↓</span> move
            </span>
            <span>
              <span className="mono">↵</span> open
            </span>
          </div>
        </>
      ) : null}
    </dialog>
  );
}
