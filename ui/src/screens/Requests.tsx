// Requests explorer: filters (query bar and facets), the dense table of
// request events, and the detail of one request with what the gateway saw.

import { useNavigate, useSearch } from '@tanstack/react-router';
import { useMemo, useState } from 'react';

import type {
  AsnInfo,
  RequestDetail as Detail,
  GatewayConfig,
  RequestFilter,
  RequestRow,
} from '../../shared/api.ts';
import {
  ACTION_LOOK,
  type Action,
  type BotClass,
  isAction,
  RANGES,
} from '../../shared/domain.ts';
import type { RequestsSearch } from '../app/search.ts';
import { useCanOperate } from '../app/session.ts';
import { FingerprintPill } from '../domain/Fingerprint.tsx';
import { ScoreBar, ScoreCell } from '../domain/ScoreBar.tsx';
import { ActionChip, ClassBadge } from '../domain/verdict.tsx';
import {
  type FilterFields,
  filterToText,
  parseFilterText,
} from '../lib/filter-text.ts';
import { clock, compact, count, dateTime, shorten } from '../lib/format.ts';
import { useCompact } from '../lib/media.ts';
import {
  useAddListEntry,
  useGatewayConfig,
  useRequestDetail,
  useRequests,
} from '../lib/queries.ts';
import { reasonWeight, thresholdsOf, weightColor } from '../lib/signals.ts';
import { toneText } from '../lib/tone.ts';
import { parseClaim } from '../lib/user-agent.ts';
import { Button } from '../ui/Button.tsx';
import { Segmented } from '../ui/controls.tsx';
import { Icon } from '../ui/Icon.tsx';
import { Dialog } from '../ui/Overlay.tsx';
import {
  AnalyticsBanner,
  EmptyState,
  PermissionNote,
  Skeleton,
} from '../ui/states.tsx';
import table from '../ui/table.module.css';
import { useCopy, useToast } from '../ui/toast-context.ts';
import styles from './Requests.module.css';

const PAGE = 100;

const ACTION_DOT: Record<string, string> = {
  allowed: 'var(--color-allowed)',
  challenged: 'var(--color-challenged)',
  blocked: 'var(--color-blocked)',
};

function toApiFilter(search: RequestsSearch): RequestFilter {
  return {
    range: search.range ?? '1h',
    ...(search.host ? { host: search.host } : {}),
    ...(search.action ? { action: search.action } : {}),
    ...(search.class ? { class: search.class } : {}),
    ...(search.reason ? { reason: search.reason } : {}),
    ...(search.asn !== undefined ? { asn: search.asn } : {}),
    ...(search.ja4 ? { ja4: search.ja4 } : {}),
    ...(search.ip_prefix ? { ip_prefix: search.ip_prefix } : {}),
    ...(search.ip_hash ? { ip_hash: search.ip_hash } : {}),
    ...(search.path ? { path: search.path } : {}),
    ...(search.min_score !== undefined ? { min_score: search.min_score } : {}),
    limit: PAGE,
  };
}

// What enforce mode does differently on a shadow host.
function wouldDiffer(row: { action: string; would_action: string }): boolean {
  return row.would_action !== '' && row.would_action !== row.action;
}

function RowAction({ row }: { row: RequestRow }) {
  if (!wouldDiffer(row)) return <ActionChip action={row.action} small dot />;
  return (
    <span
      className="hatch"
      style={{ display: 'inline-flex', borderRadius: 5, padding: 1 }}
      title={`Shadow: allowed, enforce would ${row.would_action}`}
    >
      <ActionChip action={row.would_action} small dot />
    </span>
  );
}

function QueryInput({
  filter,
  onApply,
  shown,
  total,
}: {
  filter: FilterFields;
  onApply: (filter: FilterFields) => void;
  shown: number;
  total: number;
}) {
  const text = filterToText(filter);
  // Remounted (key) when the applied filter changes, so the draft follows.
  const [draft, setDraft] = useState(text);
  const [error, setError] = useState<string | null>(null);
  return (
    <form
      className={styles.query}
      onSubmit={(event) => {
        event.preventDefault();
        const parsed = parseFilterText(draft);
        if (parsed.ok) {
          setError(null);
          onApply(parsed.filter);
        } else {
          setError(parsed.error);
        }
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          height: 36,
          padding: '0 12px',
          borderRadius: 8,
          border: `1px solid ${error ? 'var(--color-blocked)' : 'var(--color-line-strong)'}`,
          background: 'var(--color-surface-1)',
          color: 'var(--color-text-3)',
        }}
      >
        <Icon name="search" size={14} strokeWidth={1.4} />
        <input
          aria-label="Filter requests"
          aria-invalid={error ? true : undefined}
          className="mono"
          spellCheck={false}
          placeholder="host:shop.example.com action:block score>=40 asn:64496"
          value={draft}
          onChange={(event) => {
            setDraft(event.target.value);
          }}
          style={{
            flex: 1,
            minWidth: 0,
            border: 0,
            background: 'transparent',
            fontSize: 12.5,
            color: 'var(--color-text)',
          }}
        />
        <span className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
          {count(shown)} / {count(total)}
        </span>
      </div>
      {error ? (
        <div
          role="alert"
          style={{ fontSize: 12, color: 'var(--color-blocked-text)' }}
        >
          {error}
        </div>
      ) : null}
    </form>
  );
}

function Facets({
  facets,
  search,
  toggle,
}: {
  facets: Record<
    'action' | 'class' | 'host',
    { value: string; requests: number }[]
  >;
  search: RequestsSearch;
  toggle: (dimension: 'action' | 'class' | 'host', value: string) => void;
}) {
  const groups: {
    key: 'action' | 'class' | 'host';
    name: string;
    selected: string[];
  }[] = [
    { key: 'action', name: 'Action', selected: split(search.action) },
    { key: 'class', name: 'Class', selected: split(search.class) },
    {
      key: 'host',
      name: 'Host',
      selected: search.host ? search.host.split(',') : [],
    },
  ];
  return (
    <aside className={styles.facets} aria-label="Filters">
      {groups.map((group) => (
        <div key={group.key}>
          <div className={styles.facetName}>{group.name}</div>
          {facets[group.key].map((item) => {
            const on = group.selected.includes(item.value);
            const tone =
              group.key === 'action' && isAction(item.value)
                ? ACTION_LOOK[item.value].tone
                : null;
            return (
              <button
                key={item.value}
                type="button"
                aria-pressed={on}
                className={styles.facet}
                onClick={() => {
                  toggle(group.key, item.value);
                }}
              >
                <span className={styles.check}>
                  {on ? <Icon name="check" size={10} strokeWidth={2} /> : null}
                </span>
                {tone ? (
                  <span
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: 2,
                      background: ACTION_DOT[tone],
                    }}
                  />
                ) : null}
                <span
                  className={group.key === 'class' ? '' : 'mono'}
                  style={{
                    flex: 1,
                    minWidth: 0,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {item.value || '(none)'}
                </span>
                <span
                  className="mono"
                  style={{ fontSize: 11, color: 'var(--color-text-3)' }}
                >
                  {compact(item.requests)}
                </span>
              </button>
            );
          })}
          {facets[group.key].length === 0 ? (
            <div
              style={{
                fontSize: 12,
                color: 'var(--color-text-3)',
                padding: '0 6px',
              }}
            >
              No values
            </div>
          ) : null}
        </div>
      ))}
    </aside>
  );
}

function split(csv: string | undefined): string[] {
  return csv ? csv.split(',').filter(Boolean) : [];
}

function ReasonTags({ reasons }: { reasons: string[] }) {
  const shown = reasons.slice(0, 2);
  return (
    <>
      {shown.map((reason) => (
        <span key={reason} className={`mono ${styles.reasonTag}`}>
          {reason}
        </span>
      ))}
      {reasons.length > shown.length ? (
        <span
          className="mono"
          style={{ fontSize: 11, color: 'var(--color-text-3)' }}
        >
          +{reasons.length - shown.length}
        </span>
      ) : null}
    </>
  );
}

// "Claims vs observed": what the User-Agent says against what the
// connection showed, marked by the gateway's own consistency signals.
function claimRows(row: Detail['row']) {
  const claim = parseClaim(row.user_agent);
  const has = (...names: string[]) =>
    names.some((name) => row.reasons.includes(name));
  return [
    {
      k: 'TLS',
      claim: claim.browser,
      observed: shorten(row.ja4) || '—',
      ok: !has('ua_tls_mismatch'),
    },
    {
      k: 'HTTP',
      claim: claim.browser,
      observed:
        row.http_version === '2'
          ? `h2 · ${row.pseudo_order || '?'}`
          : `HTTP/${row.http_version || '?'}`,
      ok: !has('ua_h2_mismatch', 'browser_without_h2'),
    },
    {
      k: 'Hints',
      claim: claim.browser,
      observed: row.sec_ch_ua || 'no Sec-CH-UA',
      ok: !has('missing_client_hints'),
    },
    {
      k: 'Fetch',
      claim: claim.browser,
      observed: row.sec_fetch_mode
        ? `${row.sec_fetch_mode} · ${row.sec_fetch_site}`
        : 'no Sec-Fetch-*',
      ok: !has('missing_fetch_metadata'),
    },
    {
      k: 'TCP',
      claim: claim.os || 'no OS',
      observed: row.tcp_fp || '—',
      ok: !has('os_tcp_mismatch'),
    },
    {
      // The kernel's round trip reaches the nearest TCP stack, the TLS 1.3
      // handshake the TLS client: far apart, a relay sits between them.
      k: 'Path',
      claim: 'direct',
      observed:
        row.tcp_rtt_us === null && row.handshake_us === null
          ? '—'
          : `TCP ${millis(row.tcp_rtt_us)} · TLS ${millis(row.handshake_us)}`,
      ok: !has('relayed_connection'),
    },
  ];
}

function millis(micros: number | null): string {
  return micros === null ? '?' : `${(micros / 1000).toFixed(1)} ms`;
}

function RequestDetailView({
  detail,
  config,
  onClose,
}: {
  detail: Detail;
  config: GatewayConfig | undefined;
  onClose?: () => void;
}) {
  const { row } = detail;
  const canOperate = useCanOperate();
  const addEntry = useAddListEntry();
  const toast = useToast();
  const copy = useCopy();
  const thresholds = thresholdsOf(config);
  const signals = row.reasons.map((reason) => ({
    reason,
    weight: reasonWeight(reason, config),
  }));
  const maxWeight = Math.max(1, ...signals.map((s) => Math.abs(s.weight ?? 0)));
  const sum = signals.reduce((total, s) => total + (s.weight ?? 0), 0);
  const shadow = detail.mode?.mode === 'shadow' && wouldDiffer(row);
  const asn: AsnInfo | null = detail.asn;
  const rule = [
    row.ja4 ? `ja4 == "${row.ja4}"` : null,
    row.asn ? `asn == ${row.asn}` : null,
  ]
    .filter(Boolean)
    .join(' and ');

  const listEntry = (
    action: 'allow' | 'block',
    kind: 'ip' | 'ja4',
    value: string,
  ) => {
    addEntry.mutate(
      {
        kind,
        value,
        action,
        host: row.host,
        ttl: '1h',
        comment: `from request ${row.request_id}`,
      },
      {
        onSuccess: () => {
          toast(
            `${action === 'allow' ? 'Allowed' : 'Blocked'} ${value} on ${row.host} for 1h`,
          );
        },
        onError: (error) => {
          toast(error.message);
        },
      },
    );
  };

  return (
    <>
      <div className={styles.detailHead}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            gap: 12,
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
              Client · {dateTime(row.ts)}
            </div>
            <div
              className="mono"
              style={{ fontSize: 14, marginTop: 3, overflowWrap: 'anywhere' }}
            >
              {row.ip_prefix} · h:{row.ip_hash.slice(0, 8)}
            </div>
            <div
              style={{
                fontSize: 12.5,
                color: 'var(--color-text-2)',
                marginTop: 3,
              }}
            >
              {row.asn ? `AS${row.asn}` : 'no AS'} {asn?.org ?? ''}
              {asn?.country ? ` · ${asn.country}` : ''}
              {asn?.hosting ? (
                <span
                  style={{
                    fontSize: 11,
                    color: 'var(--color-text-3)',
                    border: '1px solid var(--color-line-strong)',
                    borderRadius: 4,
                    padding: '0 5px',
                    marginLeft: 6,
                  }}
                >
                  hosting
                </span>
              ) : null}
            </div>
          </div>
          <div
            style={{
              textAlign: 'right',
              display: 'flex',
              gap: 4,
              alignItems: 'flex-start',
            }}
          >
            <div>
              <div
                className="mono"
                style={{
                  fontSize: 32,
                  fontWeight: 500,
                  letterSpacing: '-0.03em',
                  lineHeight: 1,
                  color: toneText(row.score, thresholds),
                }}
              >
                {row.score}
              </div>
              <div style={{ marginTop: 6 }}>
                <ClassBadge value={row.class} />
              </div>
            </div>
            {onClose ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={onClose}
                aria-label="Close detail"
              >
                ✕
              </Button>
            ) : null}
          </div>
        </div>
        <ScoreBar
          score={row.score}
          thresholds={thresholds}
          labels={[
            config?.policy.suspicious_action ?? 'challenge',
            config?.policy.bot_action ?? 'block',
          ]}
        />
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <ActionChip action={row.action} />
          <span
            className="mono"
            style={{ fontSize: 12, color: 'var(--color-text-2)' }}
          >
            {row.host} {row.method} {row.path_group}
          </span>
          <span
            className="mono"
            style={{ fontSize: 12, color: 'var(--color-text-3)' }}
          >
            {row.status || '—'} · {row.duration_ms} ms
          </span>
        </div>
        {shadow ? (
          <div
            className="hatch"
            style={{
              marginTop: 10,
              padding: '6px 10px',
              border: '1px dashed var(--color-line-strong)',
              borderRadius: 6,
              fontSize: 12,
            }}
          >
            <span
              style={{
                background: 'var(--color-surface-1)',
                padding: '1px 4px',
                borderRadius: 3,
              }}
            >
              Host is in <b>shadow</b>. This request was let through; enforce
              would {row.would_action}.
            </span>
          </div>
        ) : null}
      </div>

      <div className={styles.detailBody}>
        <h3 className={styles.h3}>Claims vs observed</h3>
        <div className={styles.claims}>
          {claimRows(row).map((c) => (
            <div key={c.k} className={styles.claim}>
              <span style={{ color: 'var(--color-text-3)' }}>{c.k}</span>
              <span className="mono" style={{ overflowWrap: 'anywhere' }}>
                {c.claim}
              </span>
              <span
                role="img"
                aria-label={c.ok ? 'consistent' : 'inconsistent'}
                style={{
                  textAlign: 'center',
                  color: c.ok
                    ? 'var(--color-healthy)'
                    : 'var(--color-blocked-text)',
                }}
              >
                {c.ok ? '✓' : '✕'}
              </span>
              <span
                className="mono"
                style={{
                  overflowWrap: 'anywhere',
                  color: c.ok
                    ? 'var(--color-text-2)'
                    : 'var(--color-blocked-text)',
                }}
              >
                {c.observed}
              </span>
            </div>
          ))}
        </div>

        <h3 className={styles.h3}>
          Signals · sum = score{sum !== row.score ? ' (clamped 0–100)' : ''}
        </h3>
        {signals.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
            No signals: nothing looked off.
          </div>
        ) : (
          signals.map((s) => (
            <div key={s.reason} className={styles.signal}>
              <span className="mono" style={{ overflowWrap: 'anywhere' }}>
                {s.reason}
              </span>
              <div
                style={{
                  height: 6,
                  borderRadius: 3,
                  background: 'var(--color-surface-3)',
                }}
              >
                <div
                  style={{
                    height: '100%',
                    width: `${(Math.abs(s.weight ?? 0) / maxWeight) * 100}%`,
                    borderRadius: 3,
                    background:
                      s.weight === null ? 'transparent' : weightColor(s.weight),
                  }}
                />
              </div>
              <span
                className="mono"
                style={{
                  textAlign: 'right',
                  color:
                    s.weight === null
                      ? 'var(--color-text-3)'
                      : weightColor(s.weight),
                }}
              >
                {s.weight === null
                  ? '—'
                  : s.weight < 0
                    ? `−${-s.weight}`
                    : `+${s.weight}`}
              </span>
            </div>
          ))
        )}

        <h3 className={styles.h3}>Fingerprints</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {(
            [
              ['JA4', row.ja4],
              ['JA4H', row.ja4h],
              ['TCP', row.tcp_fp],
              ['H2', row.h2_fp],
              ['HDR', row.header_fp],
            ] as const
          ).map(([kind, value]) => (
            <div
              key={kind}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12,
              }}
            >
              <span
                className="mono"
                style={{
                  width: 38,
                  flex: 'none',
                  fontSize: 10.5,
                  color: 'var(--color-text-3)',
                }}
              >
                {kind}
              </span>
              <FingerprintPill value={value} kind={kind} />
            </div>
          ))}
        </div>

        <h3 className={styles.h3}>Browser probes · Web Bot Auth</h3>
        <div
          className="mono"
          style={{
            fontSize: 12,
            color: 'var(--color-text-2)',
            lineHeight: 1.7,
          }}
        >
          <div>
            probes{' '}
            {row.client_fp
              ? shorten(row.client_fp, 12, 4)
              : '— (no challenge solved)'}
          </div>
          <div>signed agent {row.signed_agent || '—'}</div>
          <div>
            model {row.model_score === null ? '—' : row.model_score.toFixed(2)}
          </div>
          <div>rate limit {row.rate_limit || '—'}</div>
        </div>
        <div
          style={{ fontSize: 11.5, color: 'var(--color-text-3)', marginTop: 8 }}
        >
          {detail.decision_available
            ? 'The gateway still holds this decision in memory.'
            : 'The gateway no longer holds this decision; this is the stored event.'}{' '}
          Request <span className="mono">{row.request_id}</span>.
        </div>
      </div>

      <div className={styles.actions}>
        {canOperate ? (
          <>
            <Button
              size="sm"
              onClick={() => {
                listEntry('allow', 'ip', row.ip_prefix);
              }}
              disabled={addEntry.isPending}
            >
              Allow {row.ip_prefix}
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => {
                listEntry('block', 'ip', row.ip_prefix);
              }}
              disabled={addEntry.isPending}
            >
              Block {row.ip_prefix}
            </Button>
            {row.ja4 ? (
              <Button
                size="sm"
                variant="dangerOutline"
                onClick={() => {
                  listEntry('block', 'ja4', row.ja4);
                }}
                disabled={addEntry.isPending}
              >
                Block JA4
              </Button>
            ) : null}
          </>
        ) : (
          <PermissionNote>
            You can look at everything; lists change with the operator role.
          </PermissionNote>
        )}
        {rule ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              copy(rule, 'rule condition');
            }}
          >
            Copy as rule
          </Button>
        ) : null}
      </div>
    </>
  );
}

function DetailPane({
  id,
  ts,
  config,
  onClose,
}: {
  id: string | undefined;
  ts: number | undefined;
  config: GatewayConfig | undefined;
  onClose?: () => void;
}) {
  const detail = useRequestDetail(id, ts);
  if (!id) {
    return (
      <EmptyState title="Pick a request">
        Its score, signals, fingerprints and what the client claimed show here.
      </EmptyState>
    );
  }
  if (detail.isError) {
    return (
      <EmptyState title="Request not found">
        {detail.error.message}. Raw events are kept for 14 days.
      </EmptyState>
    );
  }
  if (!detail.data)
    return <Skeleton loading rows={8} label="Loading request" />;
  return (
    <RequestDetailView
      detail={detail.data}
      config={config}
      {...(onClose ? { onClose } : {})}
    />
  );
}

export function Requests() {
  const search = useSearch({ from: '/requests' });
  const navigate = useNavigate({ from: '/requests' });
  const compactLayout = useCompact();
  const config = useGatewayConfig().data;
  const live = search.live ?? false;
  const range = search.range ?? '1h';
  const pages = useRequests(toApiFilter(search), live);
  const firstPage = pages.data?.pages[0];
  const rows = useMemo(
    () => pages.data?.pages.flatMap((page) => page.rows) ?? [],
    [pages.data],
  );
  const asns = useMemo(
    () =>
      new Map(
        (pages.data?.pages ?? [])
          .flatMap((page) => page.asns)
          .map((info) => [info.asn, info]),
      ),
    [pages.data],
  );
  const thresholds = thresholdsOf(config);

  const setFilter = (filter: FilterFields) => {
    void navigate({
      search: {
        range,
        ...(live ? { live } : {}),
        ...filter,
        action: filter.action?.join(','),
        class: filter.class?.join(','),
      },
    });
  };
  const toggle = (dimension: 'action' | 'class' | 'host', value: string) => {
    const current =
      dimension === 'host' ? split(search.host) : split(search[dimension]);
    const next = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    void navigate({
      search: (prev) => ({
        ...prev,
        [dimension]: next.length ? next.join(',') : undefined,
        id: undefined,
        ts: undefined,
      }),
    });
  };
  const select = (row: RequestRow) => {
    if (!row.request_id) return;
    void navigate({
      search: (prev) => ({ ...prev, id: row.request_id, ts: row.ts }),
      replace: true,
    });
  };
  const close = () => {
    void navigate({
      search: (prev) => ({ ...prev, id: undefined, ts: undefined }),
      replace: true,
    });
  };
  const filter: FilterFields = {
    ...(search.host ? { host: search.host } : {}),
    ...(search.action ? { action: split(search.action) as Action[] } : {}),
    ...(search.class ? { class: split(search.class) as BotClass[] } : {}),
    ...(search.reason ? { reason: search.reason } : {}),
    ...(search.asn !== undefined ? { asn: search.asn } : {}),
    ...(search.ja4 ? { ja4: search.ja4 } : {}),
    ...(search.ip_prefix ? { ip_prefix: search.ip_prefix } : {}),
    ...(search.ip_hash ? { ip_hash: search.ip_hash } : {}),
    ...(search.path ? { path: search.path } : {}),
    ...(search.min_score !== undefined ? { min_score: search.min_score } : {}),
  };
  const total = firstPage?.total ?? 0;
  const hasFilter = Object.keys(filter).length > 0;
  const canLoadMore = pages.hasNextPage && !pages.isFetchingNextPage;
  const loadMore = () => void pages.fetchNextPage();
  const phoneTabs: { name: string; action?: string }[] = [
    { name: 'All' },
    { name: 'Blocked', action: 'block,decoy' },
    { name: 'Challenged', action: 'challenge,captcha,throttle,tarpit' },
    { name: 'Allowed', action: 'allow' },
  ];

  return (
    <div className={styles.page}>
      <div className={styles.head}>
        <h1 className={styles.title}>Requests</h1>
        <QueryInput
          key={filterToText(filter)}
          filter={filter}
          onApply={setFilter}
          shown={rows.length}
          total={total}
        />
        <Segmented
          label="Time range"
          options={RANGES}
          value={range}
          onChange={(value) =>
            void navigate({ search: (prev) => ({ ...prev, range: value }) })
          }
        />
        <button
          type="button"
          className={styles.liveButton}
          aria-pressed={live}
          onClick={() =>
            void navigate({
              search: (prev) => ({ ...prev, live: live ? undefined : true }),
            })
          }
        >
          <span
            className={styles.liveDot}
            style={{
              background: live ? 'var(--color-healthy)' : 'var(--color-text-3)',
              animation: live
                ? 'pulse var(--duration-live) ease-in-out infinite'
                : 'none',
            }}
          />
          {live ? 'Live' : 'Paused'}
        </button>
      </div>

      <div className={styles.phoneFilters} role="group" aria-label="Filter">
        {phoneTabs.map((tab) => {
          const on = (search.action ?? '') === (tab.action ?? '');
          return (
            <button
              key={tab.name}
              type="button"
              aria-pressed={on}
              onClick={() =>
                void navigate({
                  search: (prev) => ({ ...prev, action: tab.action }),
                })
              }
              style={{
                flex: 'none',
                height: 34,
                padding: '0 14px',
                borderRadius: 999,
                fontSize: 13,
                border: `1px solid ${on ? 'var(--color-inverse)' : 'var(--color-line-strong)'}`,
                background: on ? 'var(--color-inverse)' : 'transparent',
                color: on ? 'var(--color-on-inverse)' : 'var(--color-text-2)',
              }}
            >
              {tab.name}
            </button>
          );
        })}
      </div>

      {pages.isError ? (
        <div style={{ padding: 16 }}>
          <AnalyticsBanner
            message={pages.error.message}
            onRetry={() => void pages.refetch()}
          />
        </div>
      ) : null}

      <div className={styles.body}>
        {firstPage ? (
          <Facets facets={firstPage.facets} search={search} toggle={toggle} />
        ) : null}

        <section className={styles.table} aria-label="Requests">
          <Skeleton
            loading={pages.isPending}
            rows={10}
            label="Loading requests"
          />
          {firstPage ? (
            <table className={table.table}>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Host · path</th>
                  <th>Score</th>
                  <th>Action</th>
                  <th>Reasons</th>
                  <th>ASN</th>
                  <th>JA4</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const info = asns.get(row.asn);
                  return (
                    <tr
                      key={`${row.request_id}-${row.ts}`}
                      className={row.request_id ? table.clickable : undefined}
                      aria-selected={row.request_id === search.id}
                      tabIndex={row.request_id ? 0 : undefined}
                      onClick={() => {
                        select(row);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') select(row);
                      }}
                    >
                      <td className={`mono ${table.muted}`}>{clock(row.ts)}</td>
                      <td
                        style={{
                          maxWidth: 260,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        <span
                          className="mono"
                          style={{ color: 'var(--color-text-2)' }}
                        >
                          {row.host}
                        </span>
                        <span
                          className="mono"
                          style={{ color: 'var(--color-text-3)' }}
                        >
                          {' '}
                          {row.method}{' '}
                        </span>
                        <span className="mono">{row.path_group}</span>
                      </td>
                      <td>
                        <ScoreCell
                          score={row.score}
                          thresholds={thresholds}
                          width={56}
                        />
                      </td>
                      <td>
                        <RowAction row={row} />
                      </td>
                      <td>
                        <ReasonTags reasons={row.reasons} />
                      </td>
                      <td
                        className="mono"
                        style={{ color: 'var(--color-text-2)' }}
                      >
                        {row.asn ? `AS${row.asn}` : '—'}{' '}
                        <span style={{ color: 'var(--color-text-3)' }}>
                          {info?.country ?? ''}
                        </span>
                      </td>
                      <td
                        className="mono"
                        style={{ color: 'var(--color-text-2)' }}
                      >
                        {row.ja4 ? shorten(row.ja4) : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : null}
          {firstPage && rows.length === 0 ? (
            <EmptyState
              title="No requests match these filters"
              actions={
                <>
                  {hasFilter ? (
                    <Button
                      size="sm"
                      onClick={() => {
                        setFilter({});
                      }}
                    >
                      Clear filters
                    </Button>
                  ) : null}
                  {range !== '7d' ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        void navigate({
                          search: (prev) => ({ ...prev, range: '24h' }),
                        })
                      }
                    >
                      Widen to 24h
                    </Button>
                  ) : null}
                </>
              }
            >
              {hasFilter
                ? 'Remove a filter or look further back.'
                : 'No request events in this range yet.'}
            </EmptyState>
          ) : null}
          {canLoadMore ? (
            <div className={styles.more}>
              <Button size="sm" onClick={loadMore}>
                Load older
              </Button>
            </div>
          ) : null}
        </section>

        <aside className={styles.detail} aria-label="Request detail">
          {!compactLayout ? (
            <DetailPane id={search.id} ts={search.ts} config={config} />
          ) : null}
        </aside>

        <div className={styles.cards}>
          {rows.map((row) => (
            <button
              key={`${row.request_id}-${row.ts}`}
              type="button"
              className={styles.card}
              onClick={() => {
                select(row);
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'baseline',
                  gap: 8,
                  fontSize: 13,
                }}
              >
                <span
                  className="mono"
                  style={{ color: 'var(--color-text-3)', fontSize: 11.5 }}
                >
                  {clock(row.ts)}
                </span>
                <span className="mono" style={{ color: 'var(--color-text-2)' }}>
                  {row.host}
                </span>
                <span
                  className="mono"
                  style={{
                    flex: 1,
                    minWidth: 0,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {row.path_group}
                </span>
              </div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  marginTop: 8,
                }}
              >
                <ScoreCell
                  score={row.score}
                  thresholds={thresholds}
                  width={56}
                />
                <RowAction row={row} />
                <span
                  className="mono"
                  style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 11.5,
                    color: 'var(--color-text-3)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    textAlign: 'right',
                  }}
                >
                  {row.reasons[0] ?? ''}
                </span>
              </div>
            </button>
          ))}
          {canLoadMore ? (
            <div className={styles.more}>
              <Button size="sm" onClick={loadMore}>
                Load older
              </Button>
            </div>
          ) : null}
        </div>
      </div>

      {compactLayout ? (
        <Dialog
          open={search.id !== undefined}
          onClose={close}
          label="Request detail"
          variant="sheet"
        >
          <DetailPane id={search.id} ts={search.ts} config={config} />
        </Dialog>
      ) : null}
    </div>
  );
}
