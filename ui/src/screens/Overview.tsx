// Overview: KPIs, verdicts over time, top hosts, reasons, ASNs, crawlers
// and the health of every part.

import { Link, useNavigate, useSearch } from '@tanstack/react-router';
import type { Overview as OverviewData, Status } from '../../shared/api.ts';
import { RANGES, type Range, reasonBase } from '../../shared/domain.ts';
import {
  HealthDot,
  type HealthState,
  Legend,
  Sparkline,
  VerdictChart,
} from '../domain/charts.tsx';
import { ModeBadge } from '../domain/verdict.tsx';
import { compact, count, percent } from '../lib/format.ts';
import { useGatewayConfig, useOverview, useStatus } from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { Card, PageHead } from '../ui/Card.tsx';
import { Segmented } from '../ui/controls.tsx';
import {
  AnalyticsBanner,
  EmptyState,
  GatewayDown,
  Skeleton,
} from '../ui/states.tsx';
import table from '../ui/table.module.css';
import styles from './screens.module.css';

const RANGE_NAMES: Record<Range, string> = {
  '15m': '15 minutes',
  '1h': 'hour',
  '6h': '6 hours',
  '24h': '24 hours',
  '7d': '7 days',
};

function Kpis({ data, rps }: { data: OverviewData; rps: number | null }) {
  const { series, totals } = data;
  const total = totals.allowed + totals.challenged + totals.blocked;
  const last = series[series.length - 1];
  const sum = (p: (typeof series)[number]) =>
    p.allowed + p.challenged + p.blocked;
  const peak = Math.max(0, ...series.map(sum));
  const items = [
    {
      name: 'Requests / s',
      value: compact(rps ?? (last ? sum(last) : 0)),
      sub: `peak ${compact(peak)}`,
      dot: 'var(--color-text-2)',
      fg: 'var(--color-text)',
      spark: series.map(sum),
    },
    {
      name: 'Allowed',
      value: percent(totals.allowed, total),
      sub: `${compact(last?.allowed ?? 0)}/s`,
      dot: 'var(--color-allowed)',
      fg: 'var(--color-text)',
      spark: series.map((p) => p.allowed),
    },
    {
      name: 'Challenged',
      value: percent(totals.challenged, total),
      sub: `${compact(last?.challenged ?? 0)}/s`,
      dot: 'var(--color-challenged)',
      fg: 'var(--color-challenged-text)',
      spark: series.map((p) => p.challenged),
    },
    {
      name: 'Blocked',
      value: percent(totals.blocked, total),
      sub: `${compact(last?.blocked ?? 0)}/s`,
      dot: 'var(--color-blocked)',
      fg: 'var(--color-blocked-text)',
      spark: series.map((p) => p.blocked),
    },
  ];
  return (
    <div className={styles.kpis}>
      {items.map((item, i) => (
        <div
          key={item.name}
          className={styles.kpi}
          style={{ animationDelay: `${i * 50}ms` }}
        >
          <div className={styles.kpiLabel}>
            <span className={styles.kpiDot} style={{ background: item.dot }} />
            {item.name}
          </div>
          <div className={styles.kpiValue}>
            <span
              className={`mono ${styles.kpiNumber}`}
              style={{ color: item.fg }}
            >
              {item.value}
            </span>
            <span className={`mono ${styles.kpiSub}`}>{item.sub}</span>
          </div>
          <div style={{ marginTop: 8 }}>
            <Sparkline
              values={item.spark}
              width={120}
              height={28}
              color={item.dot}
              fluid
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function ShadowBanner({ data, range }: { data: OverviewData; range: Range }) {
  const shadow = data.hosts.filter((host) => host.mode?.mode === 'shadow');
  if (data.totals.would_block === 0 && shadow.length === 0) return null;
  return (
    <Link to="/hosts" className={`hatch ${styles.shadowBanner}`}>
      <span className={styles.shadowTag}>SHADOW</span>
      <span className={styles.onGround}>
        {shadow.length > 0 ? (
          <b>
            {shadow.length} of {data.hosts.length} top hosts
          </b>
        ) : (
          <b>Shadow hosts</b>
        )}{' '}
        are only logging.{' '}
        <b className="mono">{count(data.totals.would_block)}</b> requests would
        have been blocked in the last {RANGE_NAMES[range]}.
      </span>
      <span
        className={styles.onGround}
        style={{ marginLeft: 'auto', color: 'var(--color-text-2)' }}
      >
        Review hosts →
      </span>
    </Link>
  );
}

function TopHosts({ data }: { data: OverviewData }) {
  const max = Math.max(0, ...data.hosts.flatMap((host) => host.spark));
  const seconds = data.series.length * data.step_s;
  return (
    <Card title="Top hosts" aside="req/s · blocked/s" id="hosts">
      <div className={table.wrap}>
        {data.hosts.map((host) => {
          const shadow = host.mode?.mode === 'shadow';
          const blocked = (shadow ? host.would_block : host.blocked) / seconds;
          return (
            <Link
              key={host.host}
              to="/requests"
              search={{ host: host.host }}
              className={table.row}
              style={{
                minWidth: 420,
                height: 42,
                color: 'inherit',
                textDecoration: 'none',
              }}
            >
              <span className="mono" style={{ flex: 1 }}>
                {host.host}
              </span>
              {host.mode ? <ModeBadge mode={host.mode.mode} /> : null}
              <Sparkline values={host.spark} max={max} />
              <span className="mono" style={{ width: 56, textAlign: 'right' }}>
                {compact(host.requests / seconds)}
              </span>
              <span
                className={`mono ${shadow ? 'hatch' : ''}`}
                style={{
                  width: 72,
                  textAlign: 'right',
                  padding: '1px 4px',
                  borderRadius: 4,
                  color: shadow
                    ? 'var(--color-text)'
                    : blocked === 0
                      ? 'var(--color-text-3)'
                      : 'var(--color-blocked-text)',
                }}
              >
                {shadow ? '~' : ''}
                {compact(blocked)}/s
              </span>
            </Link>
          );
        })}
        {data.hosts.length === 0 ? (
          <EmptyState title="No traffic in this range" />
        ) : null}
      </div>
    </Card>
  );
}

function Reasons({
  data,
  weights,
}: {
  data: OverviewData;
  weights: Record<string, number>;
}) {
  const max = data.reasons[0]?.requests ?? 0;
  return (
    <Card
      title="Top blocked reasons"
      aside={
        <Link to="/requests" search={{ action: 'block' }}>
          Open in explorer
        </Link>
      }
    >
      <div className={styles.bars}>
        {data.reasons.map((reason, i) => {
          const weight = weights[reasonBase(reason.reason)];
          return (
            <Link
              key={reason.reason}
              to="/requests"
              search={{ reason: reason.reason }}
              className={styles.barRow}
              style={{ color: 'inherit', textDecoration: 'none' }}
            >
              <span
                className={`mono ${styles.ellipsis}`}
                style={{ fontSize: 12 }}
              >
                {reason.reason}{' '}
                <span style={{ color: 'var(--color-text-3)' }}>
                  {weight === undefined
                    ? ''
                    : weight < 0
                      ? `−${-weight}`
                      : `+${weight}`}
                </span>
              </span>
              <div className={styles.barTrack}>
                <div
                  className={styles.barFill}
                  style={{
                    width: `${max ? (reason.requests / max) * 100 : 0}%`,
                    background: 'var(--color-blocked)',
                    opacity: 1 - i * 0.1,
                  }}
                />
              </div>
              <span
                className="mono"
                style={{
                  textAlign: 'right',
                  fontSize: 12,
                  color: 'var(--color-text-2)',
                }}
              >
                {compact(reason.requests)}
              </span>
            </Link>
          );
        })}
        {data.reasons.length === 0 ? (
          <EmptyState title="Nothing blocked">
            No request was blocked or would have been.
          </EmptyState>
        ) : null}
      </div>
    </Card>
  );
}

function Asns({ data }: { data: OverviewData }) {
  return (
    <Card title="Top ASNs" aside="share blocked">
      <div className={table.wrap}>
        {data.asns.map((row) => {
          const blocked = row.requests
            ? Math.round((row.blocked / row.requests) * 100)
            : 0;
          const challenged = row.requests
            ? Math.round((row.challenged / row.requests) * 100)
            : 0;
          return (
            <Link
              key={row.asn}
              to="/requests"
              search={{ asn: row.asn }}
              className={table.row}
              style={{
                minWidth: 420,
                color: 'inherit',
                textDecoration: 'none',
              }}
            >
              <span
                className="mono"
                style={{ width: 76, color: 'var(--color-text-2)' }}
              >
                AS{row.asn}
              </span>
              <span className={styles.ellipsis} style={{ flex: 1 }}>
                {row.info?.org ?? 'unknown'}
                {row.info?.country ? (
                  <span style={{ color: 'var(--color-text-3)' }}>
                    {' '}
                    · {row.info.country}
                  </span>
                ) : null}
              </span>
              {row.info?.hosting ? (
                <span className={styles.tag}>hosting</span>
              ) : null}
              <span className="mono" style={{ width: 56, textAlign: 'right' }}>
                {compact(row.requests)}
              </span>
              <span
                aria-hidden="true"
                style={{
                  width: 64,
                  height: 6,
                  borderRadius: 999,
                  background: 'var(--color-surface-3)',
                  display: 'flex',
                  overflow: 'hidden',
                }}
              >
                <span
                  style={{
                    width: `${blocked}%`,
                    background: 'var(--color-blocked)',
                  }}
                />
                <span
                  style={{
                    width: `${challenged}%`,
                    background: 'var(--color-challenged)',
                  }}
                />
              </span>
              <span
                className="mono"
                style={{
                  width: 36,
                  textAlign: 'right',
                  color:
                    blocked >= 40
                      ? 'var(--color-blocked-text)'
                      : 'var(--color-text-2)',
                }}
              >
                {blocked}%
              </span>
            </Link>
          );
        })}
        {data.asns.length === 0 ? (
          <EmptyState title="No AS data">
            The ASN database has no matches yet.
          </EmptyState>
        ) : null}
      </div>
    </Card>
  );
}

function Crawlers({ data }: { data: OverviewData }) {
  return (
    <Card title="Verified crawlers" aside="pass · impostors">
      <div className={table.wrap}>
        {data.crawlers.map((row) => (
          <Link
            key={row.id}
            to="/crawlers"
            search={{ crawler: row.id }}
            className={table.row}
            style={{ minWidth: 360, color: 'inherit', textDecoration: 'none' }}
          >
            <span
              aria-hidden="true"
              style={{
                width: 14,
                height: 14,
                borderRadius: 999,
                background: 'var(--color-verified-soft)',
                color: 'var(--color-verified)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <svg width="8" height="8" viewBox="0 0 10 10" aria-hidden="true">
                <path
                  d="M2 5.2l2 2L8 3"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              </svg>
            </span>
            <span style={{ flex: 1 }}>{row.id}</span>
            <span className="mono" style={{ width: 56, textAlign: 'right' }}>
              {compact(row.verified)}
            </span>
            <span
              className="mono"
              style={{
                width: 44,
                textAlign: 'right',
                color:
                  row.fake > 20
                    ? 'var(--color-blocked-text)'
                    : row.fake === 0
                      ? 'var(--color-text-3)'
                      : 'var(--color-text-2)',
              }}
            >
              {row.fake === 0 ? '0' : `+${compact(row.fake)}`}
            </span>
          </Link>
        ))}
        {data.crawlers.length === 0 ? (
          <EmptyState title="No crawler visits">
            No crawler was verified or caught in this range.
          </EmptyState>
        ) : null}
      </div>
    </Card>
  );
}

export function Health({ status }: { status: Status | undefined }) {
  if (!status) return null;
  const { gateway, health, metrics } = status;
  const tiles: {
    name: string;
    state: HealthState;
    value: string;
    sub: string;
  }[] = [
    {
      name: 'Workers',
      state: health.workers,
      value: gateway
        ? `${health.workers === 'ok' ? gateway.workers : '?'} / ${gateway.workers}`
        : '—',
      sub:
        health.workers === 'ok'
          ? 'every loop beating'
          : health.workers === 'degraded'
            ? 'a worker stalled'
            : 'no answer from /health',
    },
    {
      name: 'Admin API',
      state: health.admin,
      value: gateway
        ? `up ${compact(gateway.uptime_s / 3600)} h`
        : 'unreachable',
      sub: gateway
        ? `${count(gateway.connections_active)} connections`
        : 'unix socket',
    },
    {
      name: 'NATS',
      state: health.events,
      value:
        health.events === 'off'
          ? 'off'
          : gateway?.nats_connected
            ? 'connected'
            : 'disconnected',
      sub: gateway ? `${count(gateway.events_dropped)} events dropped` : '',
    },
    {
      name: 'ClickHouse',
      state: health.clickhouse,
      value:
        health.clickhouse === 'off'
          ? 'not configured'
          : health.clickhouse_lag_s === null
            ? health.clickhouse === 'down'
              ? 'unreachable'
              : 'no events today'
            : `lag ${compact(health.clickhouse_lag_s)}s`,
      sub: 'newest request event',
    },
    {
      name: 'XDP drops',
      state: health.xdp === 'ok' ? 'off' : health.xdp,
      value:
        metrics?.xdp_blocked === null || !metrics
          ? 'off'
          : compact(metrics.xdp_blocked),
      sub: health.xdp === 'ok' ? 'since start' : 'filter not attached',
    },
  ];
  return (
    <section aria-label="Gateway health" className={styles.healthGrid}>
      {tiles.map((tile) => (
        <div key={tile.name} className={styles.healthTile}>
          <div className={styles.healthName}>
            <HealthDot state={tile.state} size={7} />
            {tile.name}
          </div>
          <div
            className={`mono ${styles.healthValue}`}
            style={{
              color:
                tile.state === 'degraded'
                  ? 'var(--color-challenged-text)'
                  : 'var(--color-text)',
            }}
          >
            {tile.value}
          </div>
          <div className={styles.healthSub}>{tile.sub}</div>
        </div>
      ))}
    </section>
  );
}

export function Overview() {
  const range = useSearch({ from: '/' }).range ?? '1h';
  const navigate = useNavigate({ from: '/' });
  const overview = useOverview(range);
  const status = useStatus();
  const config = useGatewayConfig().data;
  const data = overview.data;
  const gateway = status.data?.gateway;
  const hostCount = data?.hosts.length ?? 0;

  const health = status.data?.health;
  const summary = health
    ? health.admin === 'down' || health.workers !== 'ok'
      ? { state: 'down' as const, text: 'Gateway needs attention' }
      : health.clickhouse === 'down' || health.clickhouse === 'degraded'
        ? { state: 'degraded' as const, text: 'Analytics degraded' }
        : { state: 'ok' as const, text: "Everything's fine" }
    : null;

  return (
    <>
      {summary && gateway ? (
        <div className={`${styles.phoneOnly} ${styles.statusLine}`}>
          <HealthDot state={summary.state} size={9} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>{summary.text}</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
              {gateway.workers} workers
              {health?.clickhouse_lag_s !== null &&
              health?.clickhouse_lag_s !== undefined
                ? ` · ClickHouse lag ${compact(health.clickhouse_lag_s)}s`
                : ''}
            </div>
          </div>
        </div>
      ) : null}
      <div className={styles.phoneOnly}>
        <Segmented
          label="Time range"
          options={RANGES}
          value={range}
          fill
          onChange={(value) => void navigate({ search: { range: value } })}
        />
      </div>
      <div className={styles.desktopOnly}>
        <PageHead
          title="Overview"
          sub={
            gateway
              ? `${hostCount} busiest hosts · ${gateway.workers} workers · updated live`
              : 'updated live'
          }
        >
          <Segmented
            label="Time range"
            options={RANGES}
            value={range}
            onChange={(value) => void navigate({ search: { range: value } })}
          />
        </PageHead>
      </div>

      {status.data?.health.admin === 'down' ? (
        <GatewayDown detail="The console cannot reach the admin API." />
      ) : null}
      {overview.isError ? (
        <AnalyticsBanner
          message={overview.error.message}
          onRetry={() => void overview.refetch()}
        />
      ) : null}

      <Skeleton
        loading={overview.isPending}
        rows={6}
        label="Loading overview"
      />

      {data ? (
        <>
          <ShadowBanner data={data} range={range} />
          <Kpis data={data} rps={status.data?.metrics?.rps ?? null} />
          <Card style={{ padding: '18px 18px 12px' }}>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                justifyContent: 'space-between',
                gap: 12,
                alignItems: 'center',
                marginBottom: 12,
              }}
            >
              <h2 style={{ fontSize: 15, fontWeight: 600 }}>
                Verdicts over time
              </h2>
              <Legend />
            </div>
            <VerdictChart series={data.series} />
          </Card>
          <div className={styles.grid2}>
            <TopHosts data={data} />
            <Reasons data={data} weights={config?.library.weights ?? {}} />
            <Asns data={data} />
            <Crawlers data={data} />
          </div>
        </>
      ) : null}

      <Health status={status.data} />

      <div className={styles.phoneOnly}>
        <Button
          block
          variant="primary"
          size="lg"
          onClick={() =>
            void navigate({ to: '/requests', search: { live: true } })
          }
        >
          Open live requests
        </Button>
      </div>
    </>
  );
}
