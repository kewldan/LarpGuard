// "Is this host ready for enforce": what enforce mode would block (on a
// shadow host) or blocks (on an enforce host), by which signals, and the
// blocked clients that look legitimate, each a link to its requests.

import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { READINESS_RANGES, type ReadinessRange } from '../../shared/api.ts';
import { ApiError } from '../lib/api.ts';
import { ago, compact, percent, shorten } from '../lib/format.ts';
import { useReadiness } from '../lib/queries.ts';
import {
  EVIDENCE_TEXT,
  readinessHeadline,
  readinessVerdict,
} from '../lib/readiness.ts';
import { Segmented } from '../ui/controls.tsx';
import { Skeleton } from '../ui/states.tsx';
import { ReasonChip } from './ReasonChip.tsx';

const VERDICT_COLOR = {
  thin: 'var(--color-line-strong)',
  ready: 'var(--color-healthy)',
  review: 'var(--color-challenged)',
} as const;

function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub: string;
}) {
  return (
    <div
      style={{
        borderRadius: 10,
        padding: '10px 12px',
        border: '1px solid var(--color-line)',
        background: 'var(--color-bg)',
        minWidth: 0,
      }}
    >
      <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
        {label}
      </div>
      <div className="mono" style={{ fontSize: 18, marginTop: 4 }}>
        {value}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>{sub}</div>
    </div>
  );
}

export function EnforceReadiness({ host }: { host: string }) {
  const [range, setRange] = useState<ReadinessRange>('24h');
  const query = useReadiness(host, range);
  const report = query.data?.host === host ? query.data : undefined;
  const enforcing = report?.mode === 'enforce';

  return (
    <section
      aria-label="Enforce readiness"
      style={{
        border: '1px solid var(--color-line)',
        borderRadius: 12,
        padding: 18,
      }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
        }}
      >
        <h2 style={{ fontSize: 15, fontWeight: 600 }}>
          {enforcing ? 'What enforce blocks' : 'Ready for enforce?'}
        </h2>
        <Segmented
          label="Readiness window"
          options={READINESS_RANGES}
          value={range}
          onChange={setRange}
        />
      </div>

      {query.isError ? (
        <div
          style={{ marginTop: 12, fontSize: 13, color: 'var(--color-text-2)' }}
        >
          {query.error instanceof ApiError && query.error.status === 503
            ? 'Needs ClickHouse: the report is built from the logged verdicts.'
            : `The report failed: ${query.error.message}`}
        </div>
      ) : !report ? (
        <div style={{ marginTop: 12 }}>
          <Skeleton loading rows={3} label="Loading the readiness report" />
        </div>
      ) : report.mode === 'off' ? (
        <div
          style={{ marginTop: 12, fontSize: 13, color: 'var(--color-text-2)' }}
        >
          The host is off: no verdicts are computed, so there is nothing to
          judge. Switch it to shadow first.
        </div>
      ) : (
        <>
          <div
            role="status"
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              marginTop: 12,
              fontSize: 13.5,
              lineHeight: 1.45,
            }}
          >
            <span
              aria-hidden="true"
              style={{
                flex: 'none',
                width: 8,
                height: 8,
                marginTop: 6,
                borderRadius: 2,
                background: VERDICT_COLOR[readinessVerdict(report)],
              }}
            />
            <span>{readinessHeadline(report)}</span>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: 8,
              marginTop: 12,
            }}
          >
            <Stat
              label={enforcing ? 'Blocked' : 'Would block'}
              value={compact(report.block.requests)}
              sub={`${percent(report.block.requests, report.requests)} · ${compact(report.block.clients)} clients`}
            />
            <Stat
              label="Of them look legitimate"
              value={compact(report.block.legit_requests)}
              sub={`${compact(report.block.legit_clients)} clients`}
            />
            <Stat
              label={enforcing ? 'Challenged' : 'Would challenge'}
              value={compact(report.challenge.requests)}
              sub={`${percent(report.challenge.requests, report.requests)} · ${compact(report.challenge.clients)} clients`}
            />
          </div>

          {report.reasons.length > 0 ? (
            <>
              <h3 style={{ fontSize: 13, fontWeight: 600, margin: '18px 0 0' }}>
                Why {enforcing ? 'they are' : 'they would be'} blocked
              </h3>
              <ul
                style={{
                  listStyle: 'none',
                  padding: 0,
                  margin: '8px 0 0',
                }}
              >
                {report.reasons.map((row) => (
                  <li
                    key={row.reason}
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      gap: '4px 10px',
                      padding: '6px 0',
                      borderTop: '1px solid var(--color-line)',
                    }}
                  >
                    <Link
                      to="/requests"
                      search={{
                        host: report.host,
                        reason: row.reason,
                        range: report.range,
                      }}
                    >
                      <ReasonChip reason={row.reason} weight={null} />
                    </Link>
                    <span
                      className="mono"
                      style={{
                        marginLeft: 'auto',
                        fontSize: 12,
                        color: 'var(--color-text-2)',
                      }}
                    >
                      {compact(row.requests)} req · {compact(row.clients)}{' '}
                      clients
                      {row.legit_clients ? (
                        <span style={{ color: 'var(--color-challenged-text)' }}>
                          {' '}
                          · {compact(row.legit_clients)} legit
                        </span>
                      ) : null}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          {report.suspects.length > 0 ? (
            <>
              <h3 style={{ fontSize: 13, fontWeight: 600, margin: '18px 0 0' }}>
                Blocked clients that look legitimate
              </h3>
              <ul
                style={{
                  listStyle: 'none',
                  padding: 0,
                  margin: '8px 0 0',
                  display: 'flex',
                  flexDirection: 'column',
                }}
              >
                {report.suspects.map((suspect) => (
                  <li
                    key={suspect.ip_hash}
                    style={{
                      padding: '10px 0',
                      borderTop: '1px solid var(--color-line)',
                      minWidth: 0,
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        alignItems: 'baseline',
                        gap: '4px 10px',
                        fontSize: 12.5,
                      }}
                    >
                      <Link
                        to="/requests"
                        search={{
                          host: report.host,
                          ip_hash: suspect.ip_hash,
                          range: report.range,
                        }}
                        className="mono"
                      >
                        {suspect.ip_prefix || shorten(suspect.ip_hash)}
                      </Link>
                      <span style={{ color: 'var(--color-text-2)' }}>
                        {suspect.evidence
                          .map((name) => EVIDENCE_TEXT[name])
                          .join(', ')}
                      </span>
                      <span
                        className="mono"
                        style={{
                          marginLeft: 'auto',
                          color: 'var(--color-text-3)',
                        }}
                      >
                        {compact(suspect.requests)} req ·{' '}
                        {ago(suspect.last_seen)}
                      </span>
                    </div>
                    <div
                      title={suspect.user_agent}
                      style={{
                        fontSize: 11.5,
                        color: 'var(--color-text-3)',
                        marginTop: 2,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {suspect.asn
                        ? `AS${suspect.asn}${suspect.as_name ? ` ${suspect.as_name}` : ''} · `
                        : ''}
                      {suspect.user_agent || 'no user agent'}
                    </div>
                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 4,
                        marginTop: 6,
                      }}
                    >
                      {suspect.reasons.map((reason) => (
                        <ReasonChip
                          key={reason}
                          reason={reason}
                          weight={null}
                        />
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          <div
            style={{
              marginTop: 12,
              fontSize: 11.5,
              color: 'var(--color-text-3)',
              lineHeight: 1.5,
            }}
          >
            A client looks legitimate when it passed a challenge or is a
            verified crawler anywhere in the window, or the blocked request was
            classed human. Challenges are not counted against readiness:
            browsers pass them.
          </div>
        </>
      )}
    </section>
  );
}

// The verdict alone over the last day, for the switch-to-enforce dialog.
export function ReadinessLine({ host }: { host: string }) {
  const report = useReadiness(host, '24h').data;
  if (report?.host !== host || report.mode === 'off') return null;
  return (
    <p
      style={{ fontSize: 13.5, color: 'var(--color-text-2)', lineHeight: 1.5 }}
    >
      Last 24 hours: {readinessHeadline(report)}
    </p>
  );
}
