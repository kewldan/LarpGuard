// Decision log: every change made through the console and every sign-in,
// newest first, with the state before and after and a revert where the
// change has an inverse.

import { useNavigate, useSearch } from '@tanstack/react-router';
import { useState } from 'react';

import type { AuditEntry, AuditKind } from '../../shared/api.ts';
import { useCanOperate } from '../app/session.ts';
import { diffLines } from '../lib/diff.ts';
import { clock } from '../lib/format.ts';
import { useAudit, useRevert } from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { QueryBar } from '../ui/controls.tsx';
import { EmptyState, ErrorState, Skeleton } from '../ui/states.tsx';
import { useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

const KINDS: { kind: AuditKind | undefined; name: string }[] = [
  { kind: undefined, name: 'All' },
  { kind: 'list', name: 'Lists' },
  { kind: 'mode', name: 'Host mode' },
  { kind: 'attack', name: 'Attack mode' },
  { kind: 'reload', name: 'Config reloads' },
  { kind: 'auth', name: 'Sign-in' },
];

const KIND_LOOK: Record<AuditKind, [string, string]> = {
  reload: ['var(--color-surface-3)', 'var(--color-text)'],
  mode: ['var(--color-surface-3)', 'var(--color-text)'],
  list: ['var(--color-blocked-soft)', 'var(--color-blocked-text)'],
  auth: ['var(--color-verified-soft)', 'var(--color-verified)'],
  attack: ['var(--color-blocked)', 'var(--color-on-blocked-chip)'],
};

function stateLines(value: unknown): string[] {
  return value === undefined || value === null
    ? []
    : JSON.stringify(value, null, 2).split('\n');
}

function dayName(ts: number): string {
  const date = new Date(ts);
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86_400_000);
  const same = (a: Date, b: Date) => a.toDateString() === b.toDateString();
  if (same(date, today)) return 'Today';
  if (same(date, yesterday)) return 'Yesterday';
  return date.toISOString().slice(0, 10);
}

function KindChip({ kind }: { kind: AuditKind }) {
  const [bg, fg] = KIND_LOOK[kind];
  return (
    <span
      className="mono"
      style={{
        fontSize: 10.5,
        padding: '1px 6px',
        borderRadius: 4,
        background: bg,
        color: fg,
      }}
    >
      {kind}
    </span>
  );
}

function Detail({ entry }: { entry: AuditEntry }) {
  const canOperate = useCanOperate();
  const revert = useRevert();
  const toast = useToast();
  const diff = diffLines(stateLines(entry.before), stateLines(entry.after));
  const facts: [string, string][] = [['Actor', entry.actor], ...entry.facts];
  return (
    <section
      aria-label="Entry detail"
      style={{
        flex: '999 1 480px',
        minWidth: 0,
        padding: '20px clamp(16px, 2.5vw, 32px) 40px',
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'flex-start',
          gap: 12,
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <KindChip kind={entry.kind} />
            <span
              className="mono"
              style={{ fontSize: 12, color: 'var(--color-text-3)' }}
            >
              {dayName(entry.ts)} {clock(entry.ts)}
            </span>
          </div>
          <h2
            style={{
              margin: '8px 0 0',
              fontSize: 22,
              fontWeight: 500,
              letterSpacing: '-0.01em',
              lineHeight: 1.25,
            }}
          >
            {entry.what}
          </h2>
        </div>
        {entry.revertible && canOperate ? (
          <Button
            disabled={revert.isPending}
            onClick={() => {
              revert.mutate(entry.id, {
                onSuccess: () => {
                  toast('Reverted');
                },
                onError: (error) => {
                  toast(error.message);
                },
              });
            }}
          >
            Revert this change
          </Button>
        ) : null}
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 10,
        }}
      >
        {facts.map(([k, v]) => (
          <div
            key={k}
            style={{
              border: '1px solid var(--color-line)',
              borderRadius: 10,
              padding: '10px 12px',
            }}
          >
            <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
              {k}
            </div>
            <div
              className="mono"
              style={{ fontSize: 13, marginTop: 3, overflowWrap: 'anywhere' }}
            >
              {v}
            </div>
          </div>
        ))}
      </div>
      {diff.length > 0 ? (
        <div
          style={{
            border: '1px solid var(--color-line)',
            borderRadius: 12,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              gap: 12,
              padding: '10px 14px',
              borderBottom: '1px solid var(--color-line)',
              background: 'var(--color-surface-1)',
              fontSize: 12,
            }}
          >
            <span className="mono">state</span>
            <span className="mono" style={{ color: 'var(--color-text-3)' }}>
              before → after
            </span>
          </div>
          <div
            className="mono"
            style={{
              padding: '8px 0',
              fontSize: 12.5,
              lineHeight: '21px',
              overflowX: 'auto',
            }}
          >
            {diff.map((line, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  minWidth: 'max-content',
                  background:
                    line.mark === '+'
                      ? 'var(--color-healthy-soft)'
                      : line.mark === '-'
                        ? 'var(--color-surface-3)'
                        : 'transparent',
                }}
              >
                <span
                  style={{
                    width: 16,
                    flex: 'none',
                    marginLeft: 14,
                    color:
                      line.mark === '+'
                        ? 'var(--color-healthy)'
                        : 'var(--color-text-3)',
                  }}
                >
                  {line.mark === ' ' ? '' : line.mark === '-' ? '−' : '+'}
                </span>
                <span
                  style={{
                    whiteSpace: 'pre',
                    paddingRight: 16,
                    color:
                      line.mark === '-'
                        ? 'var(--color-text-2)'
                        : 'var(--color-text)',
                  }}
                >
                  {line.text}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div
          style={{
            border: '1px dashed var(--color-line-strong)',
            borderRadius: 12,
            padding: 18,
            fontSize: 13,
            color: 'var(--color-text-2)',
          }}
        >
          {entry.kind === 'auth'
            ? 'Security event. No configuration change.'
            : entry.kind === 'reload'
              ? 'The gateway re-read its configuration file; the console does not see the file, so there is no diff.'
              : 'No state recorded for this change.'}
        </div>
      )}
      {entry.reverts ? (
        <div style={{ fontSize: 12.5, color: 'var(--color-text-3)' }}>
          This entry reverts an earlier change.
        </div>
      ) : null}
    </section>
  );
}

export function AuditLog() {
  const audit = useAudit();
  const search = useSearch({ from: '/log' });
  const navigate = useNavigate({ from: '/log' });
  const [q, setQ] = useState(search.q ?? '');

  if (audit.isError)
    return (
      <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />
    );
  if (!audit.data)
    return <Skeleton loading rows={8} label="Loading the decision log" />;

  const needle = q.trim().toLowerCase();
  const entries = audit.data.entries.filter(
    (entry) =>
      (!search.kind || entry.kind === search.kind) &&
      (!needle ||
        `${entry.what} ${entry.actor} ${entry.facts.flat().join(' ')}`
          .toLowerCase()
          .includes(needle)),
  );
  const current =
    entries.find((entry) => entry.id === search.entry) ?? entries[0];
  const groups: { day: string; items: AuditEntry[] }[] = [];
  for (const entry of entries) {
    const day = dayName(entry.ts);
    const group = groups.find((g) => g.day === day);
    if (group) group.items.push(entry);
    else groups.push({ day, items: [entry] });
  }

  return (
    <>
      <div
        className={styles.split}
        style={{ minHeight: 'calc(100vh - 160px)' }}
      >
        <section
          aria-label="Entries"
          className={styles.splitList}
          style={{ maxWidth: 440 }}
        >
          <div
            style={{
              padding: '18px 18px 12px',
              borderBottom: '1px solid var(--color-line)',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            <h1
              style={{
                fontSize: 22,
                fontWeight: 500,
                letterSpacing: '-0.01em',
              }}
            >
              Decision log
            </h1>
            <QueryBar
              label="Search log"
              placeholder="who, what"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
              }}
            />
            <div
              role="group"
              aria-label="Type"
              style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}
            >
              {KINDS.map(({ kind, name }) => (
                <button
                  key={name}
                  type="button"
                  aria-pressed={search.kind === kind}
                  className={styles.chipButton}
                  onClick={() => void navigate({ search: { kind } })}
                >
                  {name}
                </button>
              ))}
            </div>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            {groups.map((group) => (
              <div key={group.day}>
                <div
                  style={{
                    padding: '10px 18px 4px',
                    fontSize: 11,
                    fontWeight: 600,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    color: 'var(--color-text-3)',
                  }}
                >
                  {group.day}
                </div>
                {group.items.map((entry) => (
                  <button
                    key={entry.id}
                    type="button"
                    className={styles.listItem}
                    aria-current={entry.id === current?.id}
                    onClick={() =>
                      void navigate({
                        search: (prev) => ({ ...prev, entry: entry.id }),
                      })
                    }
                    style={{
                      flexDirection: 'row',
                      gap: 10,
                      padding: '10px 18px',
                    }}
                  >
                    <span
                      className="mono"
                      style={{
                        width: 40,
                        flex: 'none',
                        fontSize: 11.5,
                        color: 'var(--color-text-3)',
                        paddingTop: 1,
                      }}
                    >
                      {clock(entry.ts).slice(0, 5)}
                    </span>
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                        }}
                      >
                        <KindChip kind={entry.kind} />
                        <span
                          className="mono"
                          style={{
                            fontSize: 11.5,
                            color: 'var(--color-text-3)',
                          }}
                        >
                          {entry.actor}
                        </span>
                      </span>
                      <span
                        style={{
                          display: 'block',
                          fontSize: 13,
                          marginTop: 4,
                          lineHeight: 1.4,
                        }}
                      >
                        {entry.what}
                      </span>
                    </span>
                  </button>
                ))}
              </div>
            ))}
            {entries.length === 0 ? (
              <EmptyState
                title={
                  audit.data.entries.length
                    ? 'No entries match'
                    : 'Nothing logged yet'
                }
              >
                Changes made in the console and sign-ins show up here.
              </EmptyState>
            ) : null}
          </div>
        </section>
        {current ? (
          <Detail entry={current} />
        ) : (
          <section className={styles.splitDetail} />
        )}
      </div>
      <div
        style={{
          fontSize: 12,
          color: audit.data.intact
            ? 'var(--color-text-3)'
            : 'var(--color-blocked-text)',
        }}
      >
        {audit.data.intact
          ? 'Entries are append-only; each one carries the SHA-256 of the one before it, and the chain checks out.'
          : 'The log file does not check out: a line was edited or removed since it was written.'}
      </div>
    </>
  );
}
