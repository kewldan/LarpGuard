// Rate limits: the GCRA limits in effect, what they refused in the last
// hour, and the busiest client networks right now. The sliders are a
// what-if against live traffic; an operator applies the result to the
// gateway's settings layer (ADR-018), or copies the YAML for the file.

import { useEffect, useState } from 'react';

import type { ConsumerKey, Limit, Limits } from '../../shared/api.ts';
import { useCanOperate } from '../app/session.ts';
import { limitSpec, limitYaml, perSecond, rateOf } from '../lib/config-yaml.ts';
import { compact, count, duration } from '../lib/format.ts';
import { useApplySettings, useLimits } from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { PageHead } from '../ui/Card.tsx';
import { Icon } from '../ui/Icon.tsx';
import { EmptyState, ErrorState, Skeleton } from '../ui/states.tsx';
import { useCopy, useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

type Row = Limits['limits'][number];

function scope(limit: Limit): string {
  const parts = [
    limit.hosts.length ? limit.hosts.join(', ') : 'all hosts',
    ...(limit.paths.length ? [limit.paths.join(', ')] : []),
    ...(limit.methods.length ? [limit.methods.join(',')] : []),
    ...(limit.classes.length ? [`class ${limit.classes.join(',')}`] : []),
    ...(limit.statuses.length
      ? [`counts ${limit.statuses.join('/')} responses`]
      : []),
    ...(limit.mode !== 'local' ? [`${limit.mode} via Valkey`] : []),
  ];
  return parts.join(' · ');
}

// How a limit tells clients apart, as far as events can: by clearance
// session, by address hash (key `ip`), else by network.
function consumerKey(limit: Limit | undefined): ConsumerKey {
  if (limit?.key.includes('session')) return 'session';
  if (limit?.key.includes('ip')) return 'ip_hash';
  return 'ip_prefix';
}

function consumerName(by: ConsumerKey, key: string, prefix: string): string {
  if (by === 'session') return `session ${key.slice(0, 8)}…`;
  if (by === 'ip_hash') return `client ${key.slice(0, 8)}… · ${prefix}`;
  return key;
}

export function RateLimits() {
  const [by, setBy] = useState<ConsumerKey>('ip_prefix');
  const limits = useLimits(by);
  const copy = useCopy();
  const toast = useToast();
  const canOperate = useCanOperate();
  const apply = useApplySettings();
  const [selected, setSelected] = useState<string | null>(null);
  // What-if values for one limit (identified by its settings, so a reload
  // that changes them drops the what-if).
  const [whatIf, setWhatIf] = useState<{
    key: string;
    rps: number;
    burst: number;
  } | null>(null);
  const all: Row[] = [
    ...(limits.data?.limits ?? []),
    ...(limits.data?.throttle
      ? [{ ...limits.data.throttle, refused_1h: 0 }]
      : []),
  ];
  const current = all.find((limit) => limit.name === selected) ?? all[0];
  const limitKey = current
    ? `${current.name}:${current.count}:${current.period_ms}:${current.burst}`
    : '';
  const own = whatIf?.key === limitKey ? whatIf : null;
  const rps = own?.rps ?? (current ? perSecond(current) : 0);
  const burst = own?.burst ?? current?.burst ?? 0;
  const setRps = (value: number) => {
    setWhatIf({ key: limitKey, rps: value, burst });
  };
  const setBurst = (value: number) => {
    setWhatIf({ key: limitKey, rps, burst: value });
  };
  const wanted = consumerKey(current);
  useEffect(() => {
    if (wanted !== by) setBy(wanted);
  }, [wanted, by]);

  if (limits.isError)
    return (
      <ErrorState error={limits.error} onRetry={() => void limits.refetch()} />
    );
  if (!limits.data)
    return <Skeleton loading rows={8} label="Loading rate limits" />;

  const consumers = limits.data.consumers;
  const refused = limits.data.limits.reduce(
    (sum, limit) => sum + limit.refused_1h,
    0,
  );
  const maxRps = Math.max(1, ...consumers.map((c) => c.rps), rps * 1.5);
  const over = consumers.filter((c) => c.rps > rps).length;
  const dirty =
    current !== undefined &&
    (Math.abs(rps - perSecond(current)) > 1e-9 || burst !== current.burst);
  const isThrottle =
    current !== undefined &&
    limits.data.throttle !== null &&
    !limits.data.limits.some((limit) => limit.name === current.name);
  // The new rate and burst go to the settings layer: the whole
  // `rate_limits` list (or `throttle`), checked and applied by the gateway.
  const applyWhatIf = () => {
    const revision = limits.data?.revision;
    if (!current || !revision || !limits.data) return;
    const change = { rate: rateOf(rps), burst };
    const set = isThrottle
      ? { throttle: { rate: change.rate, burst, key: current.key } }
      : {
          rate_limits: limits.data.limits.map((limit) =>
            limitSpec(limit, limit.name === current.name ? change : undefined),
          ),
        };
    apply.mutate(
      { base_revision: revision, set },
      {
        onSuccess: () => {
          setWhatIf(null);
          toast(`${current.name}: ${change.rate}, burst ${burst}`);
        },
        onError: (error) => {
          toast(error.message);
        },
      },
    );
  };

  return (
    <>
      <PageHead
        title="Rate limits"
        sub="Token buckets per key. A client is limited by the strictest bucket it falls into."
      >
        <div
          className="mono"
          style={{ fontSize: 12.5, color: 'var(--color-text-2)' }}
        >
          <span
            style={{ color: 'var(--color-challenged-text)', fontWeight: 600 }}
          >
            {count(refused)}
          </span>{' '}
          refused · last 1h
        </div>
        {canOperate &&
        limits.data.editable &&
        limits.data.source === 'console' ? (
          <Button
            size="sm"
            variant="ghost"
            disabled={apply.isPending}
            onClick={() => {
              const revision = limits.data?.revision;
              if (!revision) return;
              apply.mutate(
                { base_revision: revision, reset: ['rate_limits'] },
                {
                  onSuccess: () => {
                    toast('Limits from bot-shield.yaml again');
                  },
                  onError: (error) => {
                    toast(error.message);
                  },
                },
              );
            }}
          >
            Back to the file&apos;s limits
          </Button>
        ) : null}
      </PageHead>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 16,
          alignItems: 'flex-start',
        }}
      >
        <section
          aria-label="Limits"
          style={{
            flex: '1 1 420px',
            minWidth: 0,
            border: '1px solid var(--color-line)',
            borderRadius: 12,
            overflow: 'hidden',
          }}
        >
          {all.map((limit) => (
            <button
              key={limit.name}
              type="button"
              className={styles.listItem}
              aria-current={limit.name === current?.name}
              onClick={() => {
                setSelected(limit.name);
              }}
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span
                    className="mono"
                    style={{
                      fontSize: 10.5,
                      padding: '1px 6px',
                      borderRadius: 4,
                      border: '1px solid var(--color-line-strong)',
                      color: 'var(--color-text-2)',
                    }}
                  >
                    {limit.key.join('+')}
                  </span>
                  <span
                    className="mono"
                    style={{ fontSize: 13, fontWeight: 500 }}
                  >
                    {limit.name}
                  </span>
                </div>
                <div
                  className="mono"
                  style={{
                    fontSize: 11.5,
                    color: 'var(--color-text-3)',
                    marginTop: 5,
                  }}
                >
                  {scope(limit)} · {compact(perSecond(limit))} rps · burst{' '}
                  {limit.burst} →{' '}
                  {limit.name === 'throttle' ? 'throttle (429)' : '429'}
                </div>
              </div>
              <div
                className="mono"
                style={{
                  fontSize: 14,
                  color: limit.refused_1h
                    ? 'var(--color-challenged-text)'
                    : 'var(--color-text-3)',
                }}
              >
                {compact(limit.refused_1h)}
              </div>
            </button>
          ))}
          {all.length === 0 ? (
            <EmptyState title="No rate limits">
              The configuration has no <span className="mono">rate_limits</span>
              .
            </EmptyState>
          ) : null}
        </section>

        <section
          aria-label="Limit detail"
          style={{
            flex: '2 1 560px',
            minWidth: 0,
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}
        >
          {current ? (
            <div
              style={{
                border: '1px solid var(--color-line)',
                borderRadius: 12,
                background: 'var(--color-surface-1)',
                padding: 18,
              }}
            >
              <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                Keyed by{' '}
                <span className="mono" style={{ color: 'var(--color-text-2)' }}>
                  {current.key.join(' + ')}
                </span>{' '}
                · {scope(current)} · window{' '}
                <span className="mono">{duration(current.period_ms)}</span>
              </div>
              <h2
                className="mono"
                style={{ margin: '4px 0 0', fontSize: 18, fontWeight: 500 }}
              >
                {current.name}
              </h2>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '14px 24px',
                  marginTop: 16,
                }}
              >
                <label
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    fontSize: 12,
                    color: 'var(--color-text-3)',
                  }}
                >
                  <span
                    style={{ display: 'flex', justifyContent: 'space-between' }}
                  >
                    <span>Sustained rate</span>
                    <span
                      className="mono"
                      style={{ color: 'var(--color-text)' }}
                    >
                      {compact(rps)} rps
                    </span>
                  </span>
                  <input
                    type="range"
                    min={0.1}
                    max={Math.max(10, perSecond(current) * 4)}
                    step={0.1}
                    value={rps}
                    onChange={(e) => {
                      setRps(Number(e.target.value));
                    }}
                  />
                </label>
                <label
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    fontSize: 12,
                    color: 'var(--color-text-3)',
                  }}
                >
                  <span
                    style={{ display: 'flex', justifyContent: 'space-between' }}
                  >
                    <span>Burst</span>
                    <span
                      className="mono"
                      style={{ color: 'var(--color-text)' }}
                    >
                      {burst} req
                    </span>
                  </span>
                  <input
                    type="range"
                    min={1}
                    max={Math.max(20, current.burst * 4)}
                    step={1}
                    value={burst}
                    onChange={(e) => {
                      setBurst(Number(e.target.value));
                    }}
                  />
                </label>
              </div>
              <div
                style={{
                  marginTop: 14,
                  fontSize: 12.5,
                  color: 'var(--color-text-2)',
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  gap: 8,
                }}
              >
                <span>
                  At this rate{' '}
                  <b className="mono" style={{ color: 'var(--color-text)' }}>
                    {over}
                  </b>{' '}
                  of the current top {consumers.length} networks would be over
                  it (whole network; the limit counts per{' '}
                  <span className="mono">{current.key.join('+')}</span>).
                </span>
                {dirty ? (
                  <>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        setWhatIf(null);
                      }}
                    >
                      Reset
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => {
                        copy(limitYaml(current, rps, burst), 'YAML');
                      }}
                    >
                      <Icon name="copy" size={13} /> Copy YAML
                    </Button>
                    {canOperate && limits.data.editable ? (
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={apply.isPending}
                        onClick={applyWhatIf}
                      >
                        Apply to the gateway
                      </Button>
                    ) : null}
                  </>
                ) : null}
              </div>
              {dirty ? (
                <pre className={styles.code} style={{ marginTop: 12 }}>
                  {limitYaml(current, rps, burst)}
                </pre>
              ) : null}
            </div>
          ) : null}

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
                alignItems: 'center',
                padding: '12px 16px',
                borderBottom: '1px solid var(--color-line)',
              }}
            >
              <h3 style={{ fontSize: 14, fontWeight: 600 }}>
                Top consumers · live
              </h3>
              <span
                className="mono"
                style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}
              >
                last 60s · refreshes every 3s
              </span>
            </div>
            {consumers.map((c) => {
              const limited = c.refused > 0;
              return (
                <div
                  key={c.key}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'minmax(150px, 1.3fr) 2fr 64px 84px',
                    alignItems: 'center',
                    gap: 12,
                    minHeight: 44,
                    padding: '0 16px',
                    borderBottom: '1px solid var(--color-line)',
                    fontSize: 12.5,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div
                      className="mono"
                      style={{
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {consumerName(
                        limits.data.consumers_by,
                        c.key,
                        c.ip_prefix,
                      )}
                    </div>
                    <div
                      style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}
                    >
                      {c.ip_hash_count} clients · {c.host}
                    </div>
                  </div>
                  <div
                    style={{
                      position: 'relative',
                      height: 8,
                      borderRadius: 3,
                      background: 'var(--color-surface-3)',
                    }}
                  >
                    <div
                      style={{
                        height: '100%',
                        width: `${Math.min(100, (c.rps / maxRps) * 100)}%`,
                        borderRadius: 3,
                        background:
                          c.rps > rps
                            ? 'var(--color-challenged)'
                            : 'var(--color-text-3)',
                        transition:
                          'width var(--duration-slow) var(--ease-out)',
                      }}
                    />
                    <div
                      style={{
                        position: 'absolute',
                        left: `${Math.min(100, (rps / maxRps) * 100)}%`,
                        top: -4,
                        width: 2,
                        height: 16,
                        background: 'var(--color-text)',
                      }}
                    />
                  </div>
                  <div className="mono" style={{ textAlign: 'right' }}>
                    {compact(c.rps)}/s
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span
                      className="mono"
                      style={{
                        fontSize: 11,
                        padding: '2px 7px',
                        borderRadius: 5,
                        background: limited
                          ? 'var(--color-challenged-soft)'
                          : 'transparent',
                        color: limited
                          ? 'var(--color-challenged-text)'
                          : 'var(--color-text-3)',
                        border: limited
                          ? 'none'
                          : '1px solid var(--color-line-strong)',
                      }}
                    >
                      {limited ? `${compact(c.refused)} refused` : 'ok'}
                    </span>
                  </div>
                </div>
              );
            })}
            {consumers.length === 0 ? (
              <EmptyState title="No traffic in the last minute" />
            ) : null}
            <div
              style={{
                padding: '10px 16px',
                fontSize: 11.5,
                color: 'var(--color-text-3)',
              }}
            >
              Bar = current rate. Tick = the rate above.{' '}
              {limits.data.consumers_by === 'session'
                ? 'Grouped by clearance session, the key of this limit.'
                : limits.data.consumers_by === 'ip_hash'
                  ? 'Grouped by address hash (the key ip): events carry no full address.'
                  : 'Grouped by network: one network can hold many clients.'}
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
