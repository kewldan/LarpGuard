// Lists: the gateway's operational allow and block entries (addresses or
// networks, JA4 and header-order globs), checked before rules and scoring.

import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import { type SubmitEvent, useMemo, useState } from 'react';

import type { Lists as ListsData } from '../../shared/api.ts';
import { LIST_KINDS, type ListKind } from '../../shared/domain.ts';
import { useCanOperate } from '../app/session.ts';
import { ago, compact, countdown } from '../lib/format.ts';
import { useNow } from '../lib/hooks.ts';
import {
  useAddListEntry,
  useLists,
  useRemoveListEntry,
} from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { PageHead } from '../ui/Card.tsx';
import controls from '../ui/controls.module.css';
import { QueryBar } from '../ui/controls.tsx';
import {
  EmptyState,
  ErrorState,
  PermissionNote,
  Skeleton,
} from '../ui/states.tsx';
import { useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

type Entry = ListsData['entries'][number];

const KIND_NAMES: Record<ListKind, string> = {
  ip: 'ip / cidr',
  ja4: 'ja4',
  header_fp: 'header fp',
};

const PLACEHOLDERS: Record<ListKind, string> = {
  ip: '203.0.113.0/24 or 2001:db8::/48',
  ja4: 't13d1312h2_f57a46bbacb6_* (glob)',
  header_fp: 'a1f3c9e2d4b5 (glob)',
};

const TTLS = [
  { value: '1h', label: 'ttl 1h' },
  { value: '24h', label: 'ttl 24h' },
  { value: '168h', label: 'ttl 7d' },
  { value: '', label: 'no expiry' },
];

// IPv4 network as [address, prefix length]; null for anything else.
function v4(value: string): [number, number] | null {
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/.exec(value);
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return null;
  const length = match[5] === undefined ? 32 : Number(match[5]);
  if (length > 32) return null;
  const [a = 0, b = 0, c = 0, d = 0] = octets;
  return [((a << 24) | (b << 16) | (c << 8) | d) >>> 0, length];
}

function contains(outer: string, inner: string): boolean {
  if (outer === inner) return true;
  const a = v4(outer);
  const b = v4(inner);
  if (!a || !b || a[1] > b[1]) return false;
  const mask = a[1] === 0 ? 0 : (0xffffffff << (32 - a[1])) >>> 0;
  return (a[0] & mask) >>> 0 === (b[0] & mask) >>> 0;
}

// A block entry that an allow entry covers (allow wins in the gateway).
function overriddenBy(entry: Entry, entries: Entry[]): Entry | undefined {
  if (entry.action !== 'block') return undefined;
  return entries.find(
    (other) =>
      other.action === 'allow' &&
      other.kind === entry.kind &&
      (other.host === '' || other.host === entry.host) &&
      (entry.kind === 'ip'
        ? contains(other.value, entry.value)
        : other.value === entry.value),
  );
}

function validValue(kind: ListKind, value: string): string | null {
  if (!value.trim()) return 'Enter a value.';
  if (kind === 'ip') {
    const ok = v4(value) !== null || /^[0-9a-f:]+(\/\d{1,3})?$/i.test(value);
    return ok ? null : 'Expected an IPv4 or IPv6 address or network.';
  }
  return /^[\w*.:,-]+$/.test(value) ? null : 'Letters, digits and * only.';
}

function AddForm({ tab }: { tab: 'allow' | 'block' }) {
  const add = useAddListEntry();
  const toast = useToast();
  const [kind, setKind] = useState<ListKind>('ip');
  const [value, setValue] = useState('');
  const [host, setHost] = useState('');
  const [ttl, setTtl] = useState('1h');
  const [comment, setComment] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    const problem =
      validValue(kind, value.trim()) ??
      (comment.trim() ? null : 'Say why in the comment.');
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    add.mutate(
      {
        kind,
        value: value.trim(),
        action: tab,
        ...(host.trim() ? { host: host.trim().toLowerCase() } : {}),
        ...(ttl ? { ttl } : {}),
        comment: comment.trim(),
      },
      {
        onSuccess: (entry) => {
          toast(`Added #${entry.id} to the ${tab} list`);
          setValue('');
          setComment('');
        },
        onError: (failure) => {
          setError(failure.message);
        },
      },
    );
  };

  return (
    <form aria-label="Add entry" onSubmit={submit} className={styles.addForm}>
      <select
        aria-label="Type"
        value={kind}
        onChange={(e) => {
          setKind(e.target.value as ListKind);
        }}
        className={`mono ${controls.input} ${controls.select}`}
      >
        {LIST_KINDS.map((name) => (
          <option key={name} value={name}>
            {KIND_NAMES[name]}
          </option>
        ))}
      </select>
      <input
        aria-label="Value"
        aria-invalid={error ? true : undefined}
        className={`mono ${controls.input}`}
        placeholder={PLACEHOLDERS[kind]}
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
        }}
      />
      <input
        aria-label="Host (optional)"
        className={`mono ${controls.input}`}
        placeholder="every host"
        value={host}
        onChange={(e) => {
          setHost(e.target.value);
        }}
      />
      <select
        aria-label="TTL"
        value={ttl}
        onChange={(e) => {
          setTtl(e.target.value);
        }}
        className={`mono ${controls.input} ${controls.select}`}
      >
        {TTLS.map((option) => (
          <option key={option.label} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <input
        aria-label="Comment"
        placeholder="Why? (required)"
        value={comment}
        onChange={(e) => {
          setComment(e.target.value);
        }}
        className={controls.input}
        maxLength={200}
      />
      <Button
        type="submit"
        variant={tab === 'block' ? 'danger' : 'primary'}
        disabled={add.isPending}
      >
        Add to {tab}
      </Button>
      {error ? (
        <div
          role="alert"
          style={{
            gridColumn: '1 / -1',
            fontSize: 12.5,
            color: 'var(--color-blocked-text)',
          }}
        >
          {error}
        </div>
      ) : null}
    </form>
  );
}

export function Lists() {
  const lists = useLists();
  const remove = useRemoveListEntry();
  const toast = useToast();
  const canOperate = useCanOperate();
  const search = useSearch({ from: '/lists' });
  const navigate = useNavigate({ from: '/lists' });
  const [q, setQ] = useState('');
  const tab = search.tab ?? 'block';
  const now = useNow() / 1000;
  const entries = useMemo(() => lists.data?.entries ?? [], [lists.data]);
  const counts = {
    block: entries.filter((e) => e.action === 'block').length,
    allow: entries.filter((e) => e.action === 'allow').length,
  };
  const needle = q.trim().toLowerCase();
  const rows = entries.filter(
    (entry) =>
      entry.action === tab &&
      (!search.kind || entry.kind === search.kind) &&
      (!needle ||
        `${entry.value} ${entry.comment} ${entry.added_by ?? ''} ${entry.host}`
          .toLowerCase()
          .includes(needle)),
  );

  return (
    <>
      <PageHead
        title="Lists"
        sub="Operational overrides. Checked before rules and scoring."
      />

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: '8px 16px',
          padding: '12px 14px',
          border: '1px solid var(--color-line)',
          borderRadius: 10,
          fontSize: 12.5,
        }}
      >
        <span
          className="mono"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            fontSize: 12,
          }}
        >
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 5,
              background: 'var(--color-inverse)',
              color: 'var(--color-on-inverse)',
            }}
          >
            allow
          </span>
          ›
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 5,
              background: 'var(--color-blocked)',
              color: 'var(--color-on-blocked-chip)',
            }}
          >
            block
          </span>
          ›
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 5,
              border: '1px solid var(--color-line-strong)',
            }}
          >
            rules
          </span>
          ›
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 5,
              border: '1px solid var(--color-line-strong)',
            }}
          >
            score
          </span>
        </span>
        <span style={{ color: 'var(--color-text-2)' }}>
          If an entry is on both lists, allow wins and the block entry is shown
          as overridden.
        </span>
      </div>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <div
          role="tablist"
          aria-label="List"
          style={{
            display: 'inline-flex',
            padding: 3,
            border: '1px solid var(--color-line)',
            borderRadius: 999,
            background: 'var(--color-surface-1)',
          }}
        >
          {(['block', 'allow'] as const).map((name) => (
            <button
              key={name}
              type="button"
              role="tab"
              aria-selected={tab === name}
              onClick={() =>
                void navigate({ search: (prev) => ({ ...prev, tab: name }) })
              }
              style={{
                height: 32,
                padding: '0 16px',
                border: 0,
                borderRadius: 999,
                fontSize: 13,
                background:
                  tab === name ? 'var(--color-surface-3)' : 'transparent',
                color:
                  tab === name ? 'var(--color-text)' : 'var(--color-text-3)',
              }}
            >
              {name === 'block' ? 'Block' : 'Allow'}{' '}
              <span className="mono" style={{ opacity: 0.7 }}>
                {counts[name]}
              </span>
            </button>
          ))}
        </div>
        <div
          role="group"
          aria-label="Type filter"
          style={{ display: 'flex', gap: 4 }}
        >
          {([undefined, ...LIST_KINDS] as const).map((kind) => {
            const on = search.kind === kind;
            return (
              <button
                key={kind ?? 'all'}
                type="button"
                aria-pressed={on}
                className="mono"
                onClick={() =>
                  void navigate({ search: (prev) => ({ ...prev, kind }) })
                }
                style={{
                  height: 30,
                  padding: '0 10px',
                  borderRadius: 6,
                  fontSize: 12,
                  border: `1px solid ${on ? 'var(--color-text)' : 'var(--color-line-strong)'}`,
                  background: on ? 'var(--color-surface-3)' : 'transparent',
                  color: on ? 'var(--color-text)' : 'var(--color-text-2)',
                }}
              >
                {kind ? KIND_NAMES[kind] : 'all'}
              </button>
            );
          })}
        </div>
        <div style={{ flex: '1 1 220px', maxWidth: 320, marginLeft: 'auto' }}>
          <QueryBar
            label="Search entries"
            placeholder="value, comment, author"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
            }}
          />
        </div>
      </div>

      {canOperate ? (
        <AddForm tab={tab} />
      ) : (
        <PermissionNote>
          You can see every entry; adding and removing needs the operator role.
        </PermissionNote>
      )}

      {lists.isError ? (
        <ErrorState error={lists.error} onRetry={() => void lists.refetch()} />
      ) : null}
      <Skeleton loading={lists.isPending} rows={6} label="Loading lists" />

      {lists.data ? (
        <div
          role="table"
          aria-label="Entries"
          style={{
            border: '1px solid var(--color-line)',
            borderRadius: 12,
            overflowX: 'auto',
          }}
        >
          <div style={{ minWidth: 980, fontSize: 12.5 }}>
            {/* biome-ignore lint/a11y/useFocusableInteractive: a row of a static table, not a grid. */}
            <div
              role="row"
              style={{
                display: 'grid',
                gridTemplateColumns:
                  '110px minmax(200px, 2fr) 130px minmax(160px, 2fr) 150px 90px 110px',
                color: 'var(--color-text-3)',
                fontSize: 12,
                borderBottom: '1px solid var(--color-line)',
              }}
            >
              {[
                'Type',
                'Value',
                'Expires',
                'Comment',
                'Added by',
                'Hits 24h',
                '',
              ].map((name, i) => (
                // biome-ignore lint/a11y/useFocusableInteractive: a header cell of a static table, not a grid.
                <div
                  key={name || 'actions'}
                  role="columnheader"
                  style={{
                    padding: '10px 14px',
                    textAlign: i === 5 ? 'right' : 'left',
                  }}
                >
                  {name || <span className="visually-hidden">Actions</span>}
                </div>
              ))}
            </div>
            {rows.map((entry) => {
              const override = overriddenBy(entry, entries);
              const left = entry.expires_at ? entry.expires_at - now : null;
              const total = entry.expires_at
                ? entry.expires_at - entry.created_at
                : null;
              return (
                // biome-ignore lint/a11y/useFocusableInteractive: a row of a static table, not a grid.
                <div
                  key={entry.id}
                  role="row"
                  className={styles.listRow}
                  style={{
                    display: 'grid',
                    gridTemplateColumns:
                      '110px minmax(200px, 2fr) 130px minmax(160px, 2fr) 150px 90px 110px',
                    alignItems: 'center',
                    minHeight: 48,
                    borderBottom: '1px solid var(--color-line)',
                  }}
                >
                  <div role="cell" style={{ padding: '6px 14px' }}>
                    <span
                      className="mono"
                      style={{
                        fontSize: 11,
                        padding: '2px 6px',
                        borderRadius: 4,
                        border: '1px solid var(--color-line-strong)',
                        color: 'var(--color-text-2)',
                      }}
                    >
                      {KIND_NAMES[entry.kind]}
                    </span>
                  </div>
                  <div role="cell" style={{ padding: '6px 14px', minWidth: 0 }}>
                    <div
                      className="mono"
                      style={{
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={entry.value}
                    >
                      {entry.value}
                    </div>
                    <div
                      style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}
                    >
                      #{entry.id} · {entry.host || 'every host'}
                    </div>
                    {override ? (
                      <div
                        className="hatch"
                        style={{
                          display: 'inline-block',
                          marginTop: 2,
                          fontSize: 11,
                          padding: '0 6px',
                          borderRadius: 4,
                          border: '1px dashed var(--color-line-strong)',
                        }}
                      >
                        overridden by allow #{override.id}
                      </div>
                    ) : null}
                  </div>
                  <div role="cell" style={{ padding: '6px 14px' }}>
                    <div
                      className="mono"
                      style={{
                        fontSize: 12,
                        color:
                          left !== null && left < 600
                            ? 'var(--color-challenged-text)'
                            : 'var(--color-text)',
                      }}
                    >
                      {left === null ? 'never' : countdown(left)}
                    </div>
                    {left !== null && total ? (
                      <div
                        style={{
                          width: 90,
                          height: 3,
                          borderRadius: 3,
                          background: 'var(--color-surface-3)',
                          marginTop: 4,
                        }}
                      >
                        <div
                          style={{
                            height: '100%',
                            width: `${Math.max(0, Math.min(100, (left / total) * 100))}%`,
                            borderRadius: 3,
                            background: 'var(--color-text-3)',
                          }}
                        />
                      </div>
                    ) : null}
                  </div>
                  <div
                    role="cell"
                    style={{
                      padding: '6px 14px',
                      color: 'var(--color-text-2)',
                      minWidth: 0,
                      overflowWrap: 'anywhere',
                    }}
                  >
                    {entry.comment || '—'}
                  </div>
                  <div
                    role="cell"
                    style={{ padding: '6px 14px', whiteSpace: 'nowrap' }}
                  >
                    <span className="mono" style={{ fontSize: 12 }}>
                      {entry.added_by ?? 'admin API'}
                    </span>
                    <div
                      style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}
                    >
                      {ago(entry.created_at * 1000)}
                    </div>
                  </div>
                  <div
                    role="cell"
                    className="mono"
                    style={{
                      padding: '6px 14px',
                      textAlign: 'right',
                      color: entry.hits_24h
                        ? 'var(--color-text)'
                        : 'var(--color-text-3)',
                    }}
                  >
                    {entry.hits_24h === null ? '—' : compact(entry.hits_24h)}
                  </div>
                  <div
                    role="cell"
                    style={{ padding: '6px 14px', textAlign: 'right' }}
                  >
                    {canOperate ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Remove ${entry.value}`}
                        disabled={remove.isPending}
                        onClick={() => {
                          remove.mutate(entry.id, {
                            onSuccess: () => {
                              toast(`Removed #${entry.id}`);
                            },
                            onError: (error) => {
                              toast(error.message);
                            },
                          });
                        }}
                      >
                        Remove
                      </Button>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
          {rows.length === 0 ? (
            <EmptyState title="Nothing here">
              {needle || search.kind
                ? 'No entry matches the filter.'
                : `The ${tab} list is empty. Entries you add appear at the top.`}
            </EmptyState>
          ) : null}
        </div>
      ) : null}
      <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
        Entries apply to every worker at once, survive restarts when{' '}
        <span className="mono">admin.state_file</span> is set, and every change
        is written to the <Link to="/log">decision log</Link>.
      </div>
    </>
  );
}
