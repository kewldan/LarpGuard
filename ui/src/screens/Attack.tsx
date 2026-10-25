// Attack mode: challenge every client without a clearance token, for all
// hosts or one, for a fixed time (manual) or automatically when a host's
// request rate stays above attack.auto_rps (configured in the gateway).

import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import type { AttackEntry } from '../../shared/api.ts';
import { useCanOperate } from '../app/session.ts';
import {
  compact,
  count,
  countdown,
  dateTime,
  duration,
} from '../lib/format.ts';
import { useNow } from '../lib/hooks.ts';
import {
  useAttack,
  useAttackRates,
  useAudit,
  useDisableAttack,
  useEnableAttack,
  useHosts,
} from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { Select } from '../ui/controls.tsx';
import { ErrorState, PermissionNote, Skeleton } from '../ui/states.tsx';
import { useToast } from '../ui/toast-context.ts';
import styles from './Attack.module.css';

const DURATIONS = [
  { name: '15m', ttl: '15m' },
  { name: '1h', ttl: '1h' },
  { name: '4h', ttl: '4h' },
  { name: '12h', ttl: '12h' },
];

const EFFECTS: { mark: string; text: string; bg: string; fg: string }[] = [
  {
    mark: '!',
    text: 'Every client without a valid clearance token gets the challenge, whatever its score, even on shadow hosts.',
    bg: 'var(--color-challenged-soft)',
    fg: 'var(--color-challenged-text)',
  },
  {
    mark: '✓',
    text: 'Verified crawlers and allow-listed clients still pass; allow rules still apply.',
    bg: 'var(--color-verified-soft)',
    fg: 'var(--color-verified)',
  },
  {
    mark: '✓',
    text: 'Clients that already solved a challenge keep their token and are not asked again.',
    bg: 'var(--color-allowed-soft)',
    fg: 'var(--color-allowed-text)',
  },
  {
    mark: '×',
    text: 'The state is in memory: a restart of the gateway ends attack mode.',
    bg: 'var(--color-surface-3)',
    fg: 'var(--color-text-2)',
  },
];

function RateChart({
  history,
  threshold,
}: {
  history: readonly number[];
  threshold: number;
}) {
  const max = Math.max(threshold * 1.3, ...history, 1);
  const width = 600;
  const height = 120;
  const n = history.length;
  const x = (i: number) => (n > 1 ? (i / (n - 1)) * width : 0);
  const y = (v: number) => height - (v / max) * height;
  const line = history
    .map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`)
    .join(' ');
  const area =
    n > 1
      ? `M0,${height} L${line.replace(/ /g, ' L')} L${width},${height} Z`
      : '';
  const over = threshold > 0 && (history[n - 1] ?? 0) > threshold;
  return (
    <svg
      width="100%"
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label="Requests per second, last minute"
      style={{ display: 'block', marginTop: 10 }}
    >
      {threshold > 0 ? (
        <line
          x1="0"
          x2={width}
          y1={y(threshold)}
          y2={y(threshold)}
          stroke="var(--color-text)"
          strokeDasharray="5 4"
          vectorEffect="non-scaling-stroke"
          opacity="0.6"
        />
      ) : null}
      {area ? (
        <path
          d={area}
          fill={over ? 'var(--color-blocked-soft)' : 'var(--color-surface-3)'}
        />
      ) : null}
      {n > 1 ? (
        <polyline
          points={line}
          fill="none"
          stroke={over ? 'var(--color-blocked)' : 'var(--color-text-2)'}
          strokeWidth="1.6"
          vectorEffect="non-scaling-stroke"
        />
      ) : null}
    </svg>
  );
}

const SIGNATURE_NAMES = { ip_prefix: 'network', asn: 'AS', ja4: 'JA4' };

function entryLabel(entry: AttackEntry): string {
  const host = entry.host === '*' ? 'all hosts' : entry.host;
  return entry.signature
    ? `${host} · ${SIGNATURE_NAMES[entry.signature.kind]} ${entry.signature.value}`
    : host;
}

function entryKey(entry: AttackEntry): string {
  return `${entry.host}|${entry.signature?.kind ?? ''}|${entry.signature?.value ?? ''}`;
}

export function Attack() {
  const attack = useAttack();
  const hosts = useHosts().data?.hosts ?? [];
  const audit = useAudit().data;
  const enable = useEnableAttack();
  const disable = useDisableAttack();
  const canOperate = useCanOperate();
  const toast = useToast();
  const now = useNow();
  const [target, setTarget] = useState('*');
  const [ttl, setTtl] = useState('1h');
  const data = attack.data;
  const history = useAttackRates();

  if (attack.isError)
    return (
      <ErrorState error={attack.error} onRetry={() => void attack.refetch()} />
    );
  if (!data) return <Skeleton loading rows={6} label="Loading attack mode" />;

  const active = data.entries.length > 0;
  const armed = !active && data.auto_rps > 0;
  const primary =
    data.entries.find((entry) => entry.host === '*') ?? data.entries[0];
  const left = primary?.until ? primary.until - now / 1000 : null;
  const current = data.busiest?.rps ?? data.rps ?? 0;
  const threshold = data.auto_rps;

  const hero = active
    ? {
        className: styles.heroOn,
        title: 'Attack mode on',
        short: 'On',
        sub: `${primary?.source === 'auto' ? 'Switched on automatically' : 'Switched on by an operator'} for ${data.entries.map(entryLabel).join(', ')}. ${data.entries.every((entry) => entry.signature) ? 'Only clients with that signature' : 'Every client'} without a valid token ${data.entries.every((entry) => entry.signature) ? 'are' : 'is'} being challenged.`,
        label: left !== null ? 'Time left' : 'Active for',
        value:
          left !== null
            ? countdown(left)
            : countdown(now / 1000 - (primary?.since ?? now / 1000)),
      }
    : armed
      ? {
          className: `${styles.heroArmed} hatch`,
          title: 'Auto · armed',
          short: 'Armed',
          sub: `Not active. Turns on for a host whose traffic stays above ${count(threshold)} rps, for ${duration(data.auto_duration_ms)}.`,
          label: 'Headroom on the busiest host',
          value: `${compact(Math.max(0, threshold - current))} rps`,
        }
      : {
          className: '',
          title: 'Off',
          short: 'Off',
          sub: 'Normal per-host scoring. Nothing switches on automatically (attack.auto_rps is 0).',
          label: 'Current traffic',
          value: `${compact(data.rps ?? 0)} rps`,
        };

  const switchOn = () => {
    enable.mutate(
      { host: target, ttl },
      {
        onSuccess: () => {
          toast(
            `Attack mode on for ${target === '*' ? 'all hosts' : target}, ${ttl}`,
          );
        },
        onError: (error) => {
          toast(error.message);
        },
      },
    );
  };
  const switchOff = (host: string) => {
    disable.mutate(host, {
      onSuccess: () => {
        toast(`Attack mode off for ${host === '*' ? 'all hosts' : host}`);
      },
      onError: (error) => {
        toast(error.message);
      },
    });
  };
  const extend = (entry: AttackEntry) => {
    const remaining = entry.until
      ? Math.max(0, Math.round(entry.until - now / 1000))
      : 0;
    enable.mutate(
      { host: entry.host, ttl: `${remaining + 15 * 60}s` },
      {
        onSuccess: () => {
          toast('Extended by 15 minutes');
        },
      },
    );
  };
  const activations = (audit?.entries ?? [])
    .filter((entry) => entry.kind === 'attack')
    .slice(0, 6);
  const impact = data.impact;
  const pct = (n: number) =>
    impact?.requests ? Math.round((n / impact.requests) * 100) : 0;

  return (
    <div className={styles.page}>
      <section
        aria-live="polite"
        className={`${styles.hero} ${hero.className}`}
      >
        <div className={styles.heroTop}>
          <span className={styles.heroDot} />
          Attack mode ·{' '}
          {active ? data.entries.map(entryLabel).join(', ') : 'all hosts'}
        </div>
        <div className={styles.heroRow}>
          <div>
            <h1 className={styles.heroTitle}>
              <span className={styles.wide}>{hero.title}</span>
              <span className={styles.narrow}>{hero.short}</span>
            </h1>
            <div className={styles.heroSub}>{hero.sub}</div>
          </div>
          <div className={styles.heroKpi}>
            <div style={{ fontSize: 12, opacity: 0.8 }}>{hero.label}</div>
            <div className={`mono ${styles.heroKpiValue}`}>{hero.value}</div>
          </div>
        </div>
      </section>

      <div className={styles.body}>
        <div
          role="list"
          aria-label="Attack mode state"
          className={styles.modes}
        >
          {(
            [
              ['Off', 'Normal policy', !active && !armed],
              [
                'Manual',
                'Fixed duration, then off',
                active && primary?.source !== 'auto',
              ],
              [
                'Auto',
                threshold > 0
                  ? `Per host above ${compact(threshold)} rps`
                  : 'Off in the config',
                armed || (active && primary?.source === 'auto'),
              ],
            ] as const
          ).map(([name, desc, on]) => (
            <div
              key={name}
              role="listitem"
              aria-current={on}
              className={`${styles.mode} ${name !== 'Off' ? styles.modeOn : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={styles.radio} />
                <span style={{ fontSize: 17, fontWeight: 600 }}>{name}</span>
              </div>
              <div
                className={styles.modeDesc}
                style={{
                  fontSize: 12.5,
                  color: 'var(--color-text-2)',
                  marginTop: 6,
                  lineHeight: 1.45,
                }}
              >
                {desc}
              </div>
            </div>
          ))}
        </div>

        <div className={styles.cards}>
          <section className={styles.panel}>
            <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>
              {active ? 'Active' : 'Manual'}
            </h2>
            {active ? (
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                  marginBottom: 6,
                }}
              >
                {data.entries.map((entry) => (
                  <div
                    key={entryKey(entry)}
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      gap: 10,
                      padding: '10px 12px',
                      border: '1px solid var(--color-line)',
                      borderRadius: 10,
                      background: 'var(--color-bg)',
                    }}
                  >
                    <span className="mono" style={{ flex: '1 1 160px' }}>
                      {entryLabel(entry)}
                    </span>
                    <span
                      className="mono"
                      style={{ fontSize: 12, color: 'var(--color-text-3)' }}
                    >
                      {entry.source} ·{' '}
                      {entry.until
                        ? `ends in ${countdown(entry.until - now / 1000)}`
                        : 'until switched off'}
                    </span>
                    {canOperate ? (
                      <>
                        {entry.until && !entry.signature ? (
                          <Button
                            size="sm"
                            onClick={() => {
                              extend(entry);
                            }}
                            disabled={enable.isPending}
                          >
                            +15 min
                          </Button>
                        ) : null}
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={() => {
                            switchOff(entry.host);
                          }}
                          disabled={disable.isPending}
                        >
                          Disable now
                        </Button>
                      </>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  fontSize: 13,
                  color: 'var(--color-text-2)',
                  marginBottom: 14,
                }}
              >
                Runs for a fixed time, then switches back off on its own.
              </div>
            )}
            {canOperate ? (
              <>
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 12,
                    alignItems: 'flex-end',
                    margin: '12px 0',
                  }}
                >
                  <div style={{ minWidth: 200 }}>
                    <Select
                      label="Hosts"
                      value={target}
                      onChange={(e) => {
                        setTarget(e.target.value);
                      }}
                    >
                      <option value="*">All hosts</option>
                      {hosts.map((host) => (
                        <option key={host.host} value={host.host}>
                          {host.host}
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>
                <div
                  role="group"
                  aria-label="Duration"
                  className={styles.durations}
                >
                  {DURATIONS.map((option) => (
                    <button
                      key={option.ttl}
                      type="button"
                      aria-pressed={ttl === option.ttl}
                      className={`mono ${styles.duration}`}
                      onClick={() => {
                        setTtl(option.ttl);
                      }}
                    >
                      {option.name}
                    </button>
                  ))}
                </div>
                <Button
                  variant="danger"
                  size="lg"
                  onClick={switchOn}
                  disabled={enable.isPending}
                >
                  {data.entries.some((entry) => entry.host === target)
                    ? 'Restart'
                    : 'Enable attack mode'}{' '}
                  for {ttl}
                </Button>
              </>
            ) : (
              <PermissionNote>
                Switching attack mode needs the operator role.
              </PermissionNote>
            )}

            <div style={{ marginTop: 22 }}>
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  justifyContent: 'space-between',
                  alignItems: 'baseline',
                  gap: 8,
                  marginBottom: 10,
                }}
              >
                <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                  {data.busiest
                    ? `Busiest host, ${data.busiest.host}`
                    : 'All traffic'}{' '}
                  vs auto threshold
                </div>
                <div className="mono" style={{ fontSize: 13 }}>
                  <span
                    style={{
                      color:
                        threshold > 0 && current > threshold
                          ? 'var(--color-blocked-text)'
                          : 'var(--color-text)',
                      fontWeight: 600,
                    }}
                  >
                    {compact(current)}
                  </span>{' '}
                  <span style={{ color: 'var(--color-text-3)' }}>
                    /{' '}
                    {threshold > 0 ? `${count(threshold)} rps` : 'no threshold'}
                  </span>
                </div>
              </div>
              <div
                style={{
                  position: 'relative',
                  height: 14,
                  borderRadius: 5,
                  background: 'var(--color-surface-3)',
                }}
              >
                <div
                  style={{
                    position: 'absolute',
                    inset: '0 auto 0 0',
                    width: `${Math.min(100, (current / Math.max(threshold * 1.5, current, 1)) * 100)}%`,
                    borderRadius: 5,
                    background:
                      threshold > 0 && current > threshold
                        ? 'var(--color-blocked)'
                        : 'var(--color-text-3)',
                    transition: 'width 600ms var(--ease-out)',
                  }}
                />
                {threshold > 0 ? (
                  <div
                    style={{
                      position: 'absolute',
                      left: `${(threshold / Math.max(threshold * 1.5, current, 1)) * 100}%`,
                      top: -4,
                      width: 2,
                      height: 22,
                      background: 'var(--color-text)',
                    }}
                  />
                ) : null}
              </div>
              <RateChart history={history} threshold={threshold} />
              <div
                className="mono"
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: 10.5,
                  color: 'var(--color-text-3)',
                }}
              >
                <span>−60s</span>
                <span>−30s</span>
                <span>now</span>
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: 'var(--color-text-3)',
                  marginTop: 10,
                }}
              >
                The threshold is <span className="mono">attack.auto_rps</span>{' '}
                in the gateway&apos;s config, per host, for{' '}
                {duration(data.auto_duration_ms)} once triggered.
              </div>
            </div>
          </section>

          <section className={styles.side}>
            <h2 style={{ fontSize: 15, fontWeight: 600 }}>
              What attack mode does
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {EFFECTS.map((effect) => (
                <div key={effect.text} className={styles.effect}>
                  <span
                    className={`mono ${styles.mark}`}
                    style={{ background: effect.bg, color: effect.fg }}
                  >
                    {effect.mark}
                  </span>
                  <span>{effect.text}</span>
                </div>
              ))}
            </div>
            <div
              style={{
                borderTop: '1px solid var(--color-line)',
                paddingTop: 14,
              }}
            >
              <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                Estimated impact, last 5 minutes of traffic
              </div>
              {impact && impact.requests > 0 ? (
                <>
                  <div
                    style={{
                      display: 'flex',
                      height: 10,
                      borderRadius: 4,
                      overflow: 'hidden',
                      margin: '10px 0 8px',
                    }}
                  >
                    <div
                      style={{
                        width: `${pct(impact.token)}%`,
                        background: 'var(--color-allowed)',
                      }}
                    />
                    <div
                      style={{
                        width: `${pct(impact.verified_or_listed)}%`,
                        background: 'var(--color-verified)',
                      }}
                    />
                    <div
                      style={{
                        width: `${pct(impact.rest)}%`,
                        background: 'var(--color-challenged)',
                      }}
                    />
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '6px 14px',
                      fontSize: 12,
                      color: 'var(--color-text-2)',
                    }}
                  >
                    <span>{pct(impact.token)}% hold a valid token</span>
                    <span>
                      {pct(impact.verified_or_listed)}% verified / allow-listed
                    </span>
                    <span style={{ color: 'var(--color-challenged-text)' }}>
                      {pct(impact.rest)}% challenged ≈{' '}
                      {compact(impact.rest / 300)} rps
                    </span>
                  </div>
                </>
              ) : (
                <div
                  style={{
                    fontSize: 12.5,
                    color: 'var(--color-text-3)',
                    marginTop: 8,
                  }}
                >
                  No request events in the last 5 minutes.
                </div>
              )}
            </div>
          </section>
        </div>

        <section
          style={{
            border: '1px solid var(--color-line)',
            borderRadius: 12,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              padding: '14px 16px',
              borderBottom: '1px solid var(--color-line)',
              display: 'flex',
              justifyContent: 'space-between',
              gap: 12,
            }}
          >
            <h2 style={{ fontSize: 15, fontWeight: 600 }}>Recent changes</h2>
            <span style={{ fontSize: 12.5, color: 'var(--color-text-3)' }}>
              {data.auto_activations !== null
                ? `${count(data.auto_activations)} automatic since the gateway started · `
                : ''}
              <Link to="/log" search={{ kind: 'attack' }}>
                Decision log
              </Link>
            </span>
          </div>
          {activations.map((entry) => (
            <div
              key={entry.id}
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                gap: '6px 16px',
                padding: '10px 16px',
                borderBottom: '1px solid var(--color-line)',
                fontSize: 13,
              }}
            >
              <span
                className="mono"
                style={{
                  width: 150,
                  color: 'var(--color-text-3)',
                  fontSize: 12,
                }}
              >
                {dateTime(entry.ts)}
              </span>
              <span
                className="mono"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  height: 20,
                  padding: '0 7px',
                  borderRadius: 5,
                  fontSize: 11,
                  background: 'var(--color-blocked-soft)',
                  color: 'var(--color-blocked-text)',
                }}
              >
                {entry.actor}
              </span>
              <span style={{ flex: '1 1 260px' }}>{entry.what}</span>
            </div>
          ))}
          {activations.length === 0 ? (
            <div
              style={{
                padding: '18px 16px',
                fontSize: 13,
                color: 'var(--color-text-3)',
              }}
            >
              No attack mode changes from the console yet.
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}
