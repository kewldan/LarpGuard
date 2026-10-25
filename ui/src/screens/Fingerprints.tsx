// Fingerprints: passive client signatures of the last 24 hours, by kind,
// with volume, verdict mix and a segment-by-segment comparison of two.

import { useNavigate, useSearch } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import {
  FINGERPRINT_KINDS,
  type FingerprintKind,
  type FingerprintRow,
} from '../../shared/api.ts';
import { Sparkline } from '../domain/charts.tsx';
import { DiffLine, FingerprintPill } from '../domain/Fingerprint.tsx';
import { LibraryCandidates } from '../domain/LibraryCandidates.tsx';
import { diffSegments, separatorFor } from '../lib/diff.ts';
import { ago, compact, count } from '../lib/format.ts';
import { useFingerprints, useGatewayConfig } from '../lib/queries.ts';
import { thresholdsOf } from '../lib/signals.ts';
import { toneText } from '../lib/tone.ts';
import { parseClaim } from '../lib/user-agent.ts';
import { Card, PageHead } from '../ui/Card.tsx';
import { QueryBar } from '../ui/controls.tsx';
import { AnalyticsBanner, EmptyState, Skeleton } from '../ui/states.tsx';
import table from '../ui/table.module.css';

const KIND_NAMES: Record<FingerprintKind, string> = {
  ja4: 'JA4',
  h2_fp: 'HTTP/2',
  header_fp: 'Headers',
  tcp_fp: 'TCP',
};

function KnownAs({ row }: { row: FingerprintRow }) {
  if (row.known_as) {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <span
          style={{
            fontSize: 10.5,
            padding: '1px 6px',
            borderRadius: 4,
            border: '1px solid var(--color-blocked)',
            color: 'var(--color-blocked-text)',
          }}
        >
          automation
        </span>
        <span className="mono">{row.known_as}</span>
      </span>
    );
  }
  const claim = parseClaim(row.ua_sample);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span
        style={{
          fontSize: 10.5,
          padding: '1px 6px',
          borderRadius: 4,
          border: '1px dashed var(--color-line-strong)',
          color: 'var(--color-text-3)',
        }}
      >
        claims
      </span>
      {claim.browser}
      {claim.os ? (
        <span style={{ color: 'var(--color-text-3)' }}> · {claim.os}</span>
      ) : null}
    </span>
  );
}

function VerdictMix({ row }: { row: FingerprintRow }) {
  const total = row.allowed + row.challenged + row.blocked || 1;
  const pct = (n: number) => Math.round((n / total) * 100);
  return (
    <div
      title={`allow ${pct(row.allowed)}% · challenge ${pct(row.challenged)}% · block ${pct(row.blocked)}%`}
      style={{
        display: 'flex',
        width: 120,
        height: 8,
        borderRadius: 3,
        overflow: 'hidden',
        background: 'var(--color-surface-3)',
      }}
    >
      <div
        style={{
          width: `${pct(row.allowed)}%`,
          background: 'var(--color-allowed)',
        }}
      />
      <div
        style={{
          width: `${pct(row.challenged)}%`,
          background: 'var(--color-challenged)',
        }}
      />
      <div
        style={{
          width: `${pct(row.blocked)}%`,
          background: 'var(--color-blocked)',
        }}
      />
    </div>
  );
}

function Compare({
  kind,
  a,
  b,
}: {
  kind: FingerprintKind;
  a: FingerprintRow | undefined;
  b: FingerprintRow | undefined;
}) {
  if (!a || !b) {
    return (
      <div
        style={{
          padding: '18px 0',
          fontSize: 13,
          color: 'var(--color-text-3)',
        }}
      >
        Tick two fingerprints in the table to compare them segment by segment.
      </div>
    );
  }
  const separator = separatorFor(kind);
  const tokensA = diffSegments(a.value, b.value, separator);
  const tokensB = diffSegments(b.value, a.value, separator);
  const differing = tokensB.filter((token) => token.changed).length;
  const stats: [string, string][] = [
    [
      'Segments that differ',
      `${differing} of ${Math.max(tokensA.length, tokensB.length)}`,
    ],
    ['Requests · 24h', `${compact(a.requests)} · ${compact(b.requests)}`],
    ['Clients', `${compact(a.clients)} · ${compact(b.clients)}`],
    ['Median score', `${a.median_score} · ${b.median_score}`],
  ];
  return (
    <div style={{ animation: 'rise 260ms var(--ease-out) both' }}>
      {(
        [
          ['A', a, tokensA, false],
          ['B', b, tokensB, true],
        ] as const
      ).map(([slot, row, tokens, highlight]) => (
        <div
          key={slot}
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '6px 16px',
            alignItems: 'baseline',
            padding: '8px 0',
            borderBottom: '1px solid var(--color-line)',
          }}
        >
          <div
            style={{
              width: 200,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 12.5,
            }}
          >
            <span
              className="mono"
              style={{
                width: 18,
                height: 18,
                borderRadius: 5,
                background: 'var(--color-inverse)',
                color: 'var(--color-on-inverse)',
                fontSize: 10,
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {slot}
            </span>
            <span
              style={{
                minWidth: 0,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {row.known_as ?? parseClaim(row.ua_sample).browser}
            </span>
          </div>
          <div style={{ flex: '1 1 420px' }}>
            <DiffLine tokens={tokens} highlight={highlight} />
          </div>
        </div>
      ))}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12,
          marginTop: 14,
        }}
      >
        {stats.map(([k, v]) => (
          <div
            key={k}
            style={{
              border: '1px solid var(--color-line)',
              borderRadius: 10,
              padding: '10px 12px',
              background: 'var(--color-bg)',
            }}
          >
            <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
              {k}
            </div>
            <div className="mono" style={{ fontSize: 14, marginTop: 4 }}>
              {v}
            </div>
          </div>
        ))}
      </div>
      <p
        style={{
          margin: '12px 0 0',
          fontSize: 13,
          color: 'var(--color-text-2)',
          lineHeight: 1.5,
        }}
      >
        {differing === 0
          ? 'The two are identical.'
          : `Segments of B that differ from A are marked. ${kind === 'ja4' ? 'In JA4 the first part is the protocol, version and counts, the second the cipher hash, the third the extension hash.' : ''}`}
      </p>
    </div>
  );
}

export function Fingerprints() {
  const search = useSearch({ from: '/fingerprints' });
  const navigate = useNavigate({ from: '/fingerprints' });
  const kind = search.kind ?? 'ja4';
  const [q, setQ] = useState(search.q ?? '');
  useEffect(() => {
    const timer = setTimeout(() => {
      if (q !== (search.q ?? '')) {
        void navigate({
          search: (prev) => ({ ...prev, q: q || undefined }),
          replace: true,
        });
      }
    }, 250);
    return () => {
      clearTimeout(timer);
    };
  }, [q, search.q, navigate]);
  const data = useFingerprints(kind, search.q ?? '');
  const config = useGatewayConfig().data;
  const thresholds = thresholdsOf(config);
  const rows = data.data?.rows ?? [];
  const max = Math.max(0, ...rows.flatMap((row) => row.hourly));
  const selected = [search.a, search.b].filter(
    (v): v is string => v !== undefined,
  );
  const toggle = (value: string) => {
    const next = selected.includes(value)
      ? selected.filter((v) => v !== value)
      : [...selected, value].slice(-2);
    void navigate({
      search: (prev) => ({ ...prev, a: next[0], b: next[1] }),
      replace: true,
    });
  };
  const rowA = rows.find((row) => row.value === search.a);
  const rowB = rows.find((row) => row.value === search.b);

  return (
    <>
      <PageHead
        title="Fingerprints"
        sub="Passive client signatures, last 24h. Tick two rows to compare them."
      >
        <div style={{ flex: '0 1 300px' }}>
          <QueryBar
            label="Filter fingerprints"
            placeholder="t13d1516h2, 8daaf6152771…"
            value={q}
            onChange={(event) => {
              setQ(event.target.value);
            }}
          />
        </div>
      </PageHead>

      <div
        role="tablist"
        aria-label="Fingerprint type"
        style={{
          display: 'flex',
          gap: 2,
          borderBottom: '1px solid var(--color-line)',
          overflowX: 'auto',
        }}
      >
        {FINGERPRINT_KINDS.map((name) => {
          const on = name === kind;
          const distinct = data.data?.kinds.find(
            (k) => k.kind === name,
          )?.distinct;
          return (
            <button
              key={name}
              type="button"
              role="tab"
              aria-selected={on}
              className="mono"
              onClick={() => void navigate({ search: { kind: name } })}
              style={{
                height: 38,
                padding: '0 14px',
                border: 0,
                background: 'transparent',
                fontSize: 12.5,
                color: on ? 'var(--color-text)' : 'var(--color-text-3)',
                boxShadow: on ? 'inset 0 -2px 0 var(--color-text)' : 'none',
                whiteSpace: 'nowrap',
              }}
            >
              {KIND_NAMES[name]}{' '}
              <span style={{ color: 'var(--color-text-3)' }}>
                {distinct === undefined ? '' : count(distinct)}
              </span>
            </button>
          );
        })}
      </div>

      {data.isError ? (
        <AnalyticsBanner
          message={data.error.message}
          onRetry={() => void data.refetch()}
        />
      ) : null}

      <Card flush plain>
        <Skeleton
          loading={data.isPending}
          rows={8}
          label="Loading fingerprints"
        />
        {data.data ? (
          <div className={table.wrap}>
            <table
              className={table.table}
              style={{ minWidth: 980, fontSize: 12.5 }}
            >
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <span className="visually-hidden">Compare</span>
                  </th>
                  <th>Fingerprint</th>
                  <th>Known as</th>
                  <th className={table.num}>req / h</th>
                  <th>24h</th>
                  <th>Verdicts</th>
                  <th className={table.num}>Median</th>
                  <th>First · last seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const slot =
                    search.a === row.value
                      ? 'A'
                      : search.b === row.value
                        ? 'B'
                        : null;
                  return (
                    <tr
                      key={row.value}
                      aria-selected={slot !== null}
                      style={{ height: 44 }}
                    >
                      <td style={{ paddingRight: 0 }}>
                        <button
                          type="button"
                          role="checkbox"
                          aria-checked={slot !== null}
                          aria-label={`Compare ${row.value}`}
                          onClick={() => {
                            toggle(row.value);
                          }}
                          style={{
                            width: 18,
                            height: 18,
                            padding: 0,
                            borderRadius: 5,
                            border: `1px solid ${slot ? 'var(--color-inverse)' : 'var(--color-line-strong)'}`,
                            background: slot
                              ? 'var(--color-inverse)'
                              : 'transparent',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          <span
                            className="mono"
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              color: 'var(--color-on-inverse)',
                            }}
                          >
                            {slot ?? ''}
                          </span>
                        </button>
                      </td>
                      <td>
                        <FingerprintPill
                          value={row.value}
                          kind={KIND_NAMES[kind]}
                        />
                      </td>
                      <td>
                        <KnownAs row={row} />
                      </td>
                      <td className={table.num}>
                        {compact(row.requests / 24)}
                      </td>
                      <td>
                        <Sparkline
                          values={row.hourly}
                          width={96}
                          height={22}
                          max={max}
                          color="var(--color-text-2)"
                        />
                      </td>
                      <td>
                        <VerdictMix row={row} />
                      </td>
                      <td
                        className={table.num}
                        style={{
                          color: toneText(row.median_score, thresholds),
                        }}
                      >
                        {row.median_score}
                      </td>
                      <td className={`mono ${table.muted}`}>
                        {ago(row.first_seen)} · {ago(row.last_seen)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {rows.length === 0 ? (
              <EmptyState
                title={
                  search.q
                    ? `No fingerprints match “${search.q}”`
                    : 'No fingerprints in the last 24 hours'
                }
              />
            ) : null}
          </div>
        ) : null}
      </Card>

      <Card style={{ padding: 18 }} aria-label="Compare">
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'space-between',
            gap: 8,
            marginBottom: 12,
          }}
        >
          <h2 style={{ fontSize: 15, fontWeight: 600 }}>Compare</h2>
          <span style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
            {rowA && rowB
              ? `${KIND_NAMES[kind]} · A vs B`
              : `${selected.length} of 2 picked`}
          </span>
        </div>
        <Compare kind={kind} a={rowA} b={rowB} />
      </Card>

      <LibraryCandidates />
    </>
  );
}
