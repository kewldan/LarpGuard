// Hosts & policy: every host the gateway knows, its mode and where the
// mode comes from; switching shadow/enforce from the console (an override
// that beats the config until reverted), and the policy settings in effect.

import { useNavigate, useSearch } from '@tanstack/react-router';
import { useState } from 'react';

import type { GatewayConfig, HostRow } from '../../shared/api.ts';
import type { HostMode } from '../../shared/domain.ts';
import { useCanOperate } from '../app/session.ts';
import { ActionChip, ModeBadge } from '../domain/verdict.tsx';
import { compact, count, duration } from '../lib/format.ts';
import {
  useClearMode,
  useGatewayConfig,
  useHosts,
  useSetMode,
} from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { Dialog } from '../ui/Overlay.tsx';
import {
  EmptyState,
  ErrorState,
  PermissionNote,
  Skeleton,
} from '../ui/states.tsx';
import { useCopy, useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

const SOURCE_NAMES: Record<HostRow['source'], string> = {
  console: 'console override',
  'policy.hosts': 'policy.hosts in the config',
  labels: 'docker labels',
  mode: 'global mode',
};

const MODE_TEXT: Record<HostMode, string> = {
  shadow: 'Compute verdicts and log what would happen. Nothing is blocked.',
  enforce: 'Carry verdicts out: challenge, throttle, block.',
  off: 'Plain proxying: no verdicts and no rate limits.',
};

function Mix({ host }: { host: HostRow }) {
  const total = host.requests || 1;
  const allowed = Math.max(0, host.requests - host.challenged - host.blocked);
  return (
    <div
      title={`allow ${Math.round((allowed / total) * 100)}% · challenge ${Math.round((host.challenged / total) * 100)}% · block ${Math.round((host.blocked / total) * 100)}%`}
      style={{
        display: 'flex',
        height: 4,
        borderRadius: 2,
        overflow: 'hidden',
        background: 'var(--color-surface-3)',
        marginTop: 8,
      }}
    >
      <div
        style={{
          width: `${(allowed / total) * 100}%`,
          background: 'var(--color-allowed)',
        }}
      />
      <div
        style={{
          width: `${(host.challenged / total) * 100}%`,
          background: 'var(--color-challenged)',
        }}
      />
      <div
        style={{
          width: `${(host.blocked / total) * 100}%`,
          background: 'var(--color-blocked)',
        }}
      />
    </div>
  );
}

function PolicySettings({ config }: { config: GatewayConfig }) {
  return (
    <>
      <section
        style={{
          border: '1px solid var(--color-line)',
          borderRadius: 12,
          padding: 18,
        }}
      >
        <h2 style={{ fontSize: 15, fontWeight: 600 }}>Verdicts</h2>
        <div
          style={{
            fontSize: 12.5,
            color: 'var(--color-text-3)',
            margin: '4px 0 12px',
          }}
        >
          What enforce mode does per class (the same for every host).
        </div>
        <div className={styles.facts}>
          {(
            [
              [
                `suspicious · score ≥ ${config.policy.suspicious_threshold}`,
                config.policy.suspicious_action,
              ],
              [
                `bot · score ≥ ${config.policy.bot_threshold}`,
                config.policy.bot_action,
              ],
              ['verified bot', config.policy.verified_bot_action],
              [
                'AI crawlers',
                config.crawlers.ai_action ?? 'scored like anyone',
              ],
            ] as const
          ).map(([k, v]) => (
            <div key={k} className={styles.fact}>
              <span className={styles.factKey}>{k}</span>
              {v === 'scored like anyone' ? (
                <span>{v}</span>
              ) : (
                <ActionChip action={v} small />
              )}
            </div>
          ))}
        </div>
      </section>
      <section
        style={{
          border: '1px solid var(--color-line)',
          borderRadius: 12,
          padding: 18,
        }}
      >
        <h2 style={{ fontSize: 15, fontWeight: 600 }}>Challenge and CAPTCHA</h2>
        <div className={styles.facts} style={{ marginTop: 12 }}>
          {(
            [
              [
                'Proof of work, suspicious',
                `${config.challenge.suspicious_difficulty} bits`,
              ],
              ['Proof of work, bot', `${config.challenge.bot_difficulty} bits`],
              [
                'Clearance token',
                `${duration(config.challenge.token_ttl_ms)} · −${config.challenge.token_credit} score`,
              ],
              [
                'CAPTCHA',
                config.captcha.provider
                  ? `${config.captcha.provider} · ${config.captcha.rounds} rounds`
                  : 'off',
              ],
              ['Escalate to CAPTCHA', config.captcha.escalate ? 'yes' : 'no'],
            ] as const
          ).map(([k, v]) => (
            <div key={k} className={styles.fact}>
              <span className={styles.factKey}>{k}</span>
              <span className="mono">{v}</span>
            </div>
          ))}
        </div>
        <div
          style={{ fontSize: 12, color: 'var(--color-text-3)', marginTop: 10 }}
        >
          These live in <span className="mono">bot-shield.yaml</span>; change
          them there and reload.
        </div>
      </section>
    </>
  );
}

export function Hosts() {
  const hosts = useHosts();
  const config = useGatewayConfig().data;
  const search = useSearch({ from: '/hosts' });
  const navigate = useNavigate({ from: '/hosts' });
  const canOperate = useCanOperate();
  const setMode = useSetMode();
  const clearMode = useClearMode();
  const toast = useToast();
  const copy = useCopy();
  const [pending, setPending] = useState<HostMode | null>(null);

  if (hosts.isError)
    return (
      <ErrorState error={hosts.error} onRetry={() => void hosts.refetch()} />
    );
  if (!hosts.data) return <Skeleton loading rows={8} label="Loading hosts" />;

  const list = hosts.data.hosts;
  const current = list.find((host) => host.host === search.host) ?? list[0];
  const shadowCount = list.filter((host) => host.mode === 'shadow').length;

  const apply = (mode: HostMode) => {
    if (!current) return;
    setMode.mutate(
      { host: current.host, mode },
      {
        onSuccess: () => {
          toast(`${current.host} is now in ${mode}`);
        },
        onError: (error) => {
          toast(error.message);
        },
      },
    );
    setPending(null);
  };

  return (
    <div className={styles.split} style={{ minHeight: 'calc(100vh - 130px)' }}>
      <aside className={styles.splitList} aria-label="Hosts">
        <div
          style={{
            padding: '14px 16px',
            borderBottom: '1px solid var(--color-line)',
          }}
        >
          <h1 style={{ fontSize: 17, fontWeight: 600 }}>Hosts &amp; policy</h1>
          <div
            style={{
              fontSize: 11.5,
              color: 'var(--color-text-3)',
              marginTop: 4,
            }}
          >
            From traffic, the config and labels · {shadowCount} of {list.length}{' '}
            in shadow · default {hosts.data.default_mode}
          </div>
        </div>
        <div style={{ flex: 1, overflow: 'auto' }}>
          {list.map((host) => (
            <button
              key={host.host}
              type="button"
              className={styles.listItem}
              aria-current={host.host === current?.host}
              onClick={() => void navigate({ search: { host: host.host } })}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
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
                  {host.host}
                </span>
                <ModeBadge mode={host.mode} />
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: 10,
                  fontSize: 11.5,
                  color: 'var(--color-text-3)',
                }}
              >
                <span className="mono">{compact(host.rps)} rps</span>
                <span>
                  {host.source === 'console' ? 'console override' : host.source}
                </span>
              </div>
              <Mix host={host} />
            </button>
          ))}
          {list.length === 0 ? (
            <EmptyState title="No hosts yet">
              Hosts appear once traffic arrives.
            </EmptyState>
          ) : null}
        </div>
      </aside>

      {current ? (
        <section className={styles.splitDetail} aria-label={current.host}>
          <div className={styles.detailHead}>
            <div style={{ minWidth: 0, marginRight: 'auto' }}>
              <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
                Route <span className="mono">{current.route}</span> ·
                certificate{' '}
                <span className="mono">
                  {current.certificate ? 'yes' : 'none'}
                </span>
                {current.rate_limits.length ? (
                  <>
                    {' '}
                    · limits{' '}
                    <span className="mono">
                      {current.rate_limits.join(', ')}
                    </span>
                  </>
                ) : null}
              </div>
              <div
                className="mono"
                style={{ fontSize: 17, fontWeight: 500, marginTop: 2 }}
              >
                {current.host}
              </div>
            </div>
          </div>
          <div
            style={{ display: 'flex', flexWrap: 'wrap', gap: 16, padding: 20 }}
          >
            <div
              style={{
                flex: '999 1 460px',
                minWidth: 0,
                display: 'flex',
                flexDirection: 'column',
                gap: 16,
              }}
            >
              <section
                style={{
                  border: '1px solid var(--color-line)',
                  borderRadius: 12,
                  padding: 18,
                  background: 'var(--color-surface-1)',
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
                  <h2 style={{ fontSize: 15, fontWeight: 600 }}>Mode</h2>
                  <span
                    className="mono"
                    style={{
                      fontSize: 11.5,
                      padding: '2px 8px',
                      borderRadius: 999,
                      border: '1px solid var(--color-line-strong)',
                      color: 'var(--color-text-2)',
                    }}
                  >
                    source: {SOURCE_NAMES[current.source]}
                  </span>
                </div>
                <div
                  role="radiogroup"
                  aria-label="Mode"
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
                    gap: 8,
                    marginTop: 14,
                  }}
                >
                  {(['shadow', 'enforce', 'off'] as const).map((mode) => {
                    const on = current.mode === mode;
                    return (
                      <button
                        key={mode}
                        type="button"
                        role="radio"
                        aria-checked={on}
                        disabled={!canOperate || setMode.isPending}
                        onClick={() => {
                          if (!on) setPending(mode);
                        }}
                        className={mode === 'shadow' ? 'hatch' : undefined}
                        style={{
                          textAlign: 'left',
                          padding: 14,
                          borderRadius: 10,
                          border: `1px ${mode === 'shadow' ? 'dashed' : 'solid'} ${on ? 'var(--color-text)' : 'var(--color-line-strong)'}`,
                          background:
                            on && mode === 'enforce'
                              ? 'var(--color-surface-3)'
                              : undefined,
                          opacity: 1,
                          cursor: canOperate ? 'pointer' : 'default',
                          boxShadow: on
                            ? 'inset 0 0 0 1px var(--color-text)'
                            : 'none',
                        }}
                      >
                        <div
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            letterSpacing: '0.08em',
                          }}
                        >
                          {mode.toUpperCase()}
                        </div>
                        <div
                          style={{
                            fontSize: 12.5,
                            color: 'var(--color-text-2)',
                            marginTop: 6,
                            lineHeight: 1.45,
                          }}
                        >
                          {MODE_TEXT[mode]}
                        </div>
                      </button>
                    );
                  })}
                </div>
                {current.source === 'console' ? (
                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      gap: 10,
                      marginTop: 12,
                      padding: '10px 12px',
                      borderRadius: 8,
                      border: '1px solid var(--color-line-strong)',
                      fontSize: 12.5,
                    }}
                  >
                    <span style={{ flex: 1 }}>
                      Console override: this beats{' '}
                      <span className="mono">policy.hosts</span> and labels
                      until you revert it.
                    </span>
                    {canOperate ? (
                      <Button
                        size="sm"
                        disabled={clearMode.isPending}
                        onClick={() => {
                          clearMode.mutate(current.host, {
                            onSuccess: () => {
                              toast(
                                `${current.host}: back to its configured mode`,
                              );
                            },
                            onError: (error) => {
                              toast(error.message);
                            },
                          });
                        }}
                      >
                        Revert to source
                      </Button>
                    ) : null}
                  </div>
                ) : null}
                <div
                  className={
                    current.mode === 'shadow' && current.would_block
                      ? 'hatch'
                      : undefined
                  }
                  style={{
                    marginTop: 12,
                    padding: '8px 10px',
                    borderRadius: 8,
                    border: '1px dashed var(--color-line-strong)',
                    fontSize: 13,
                  }}
                >
                  <span
                    style={{
                      background: 'var(--color-surface-1)',
                      padding: '1px 4px',
                      borderRadius: 3,
                    }}
                  >
                    {current.mode === 'shadow'
                      ? `In the last hour ${count(current.would_block)} requests would have been blocked; nothing was.`
                      : current.mode === 'enforce'
                        ? `In the last hour ${count(current.blocked)} requests were blocked and ${count(current.challenged)} challenged.`
                        : 'No verdicts: requests pass without checks or limits.'}
                  </span>
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
                    gap: 8,
                    marginTop: 12,
                  }}
                >
                  {(
                    [
                      [
                        'Allowed',
                        Math.max(
                          0,
                          current.requests -
                            current.challenged -
                            current.blocked,
                        ),
                        'var(--color-allowed)',
                      ],
                      [
                        'Challenged',
                        current.challenged,
                        'var(--color-challenged)',
                      ],
                      [
                        current.mode === 'shadow' ? 'Would block' : 'Blocked',
                        current.mode === 'shadow'
                          ? current.would_block
                          : current.blocked,
                        'var(--color-blocked)',
                      ],
                    ] as const
                  ).map(([name, value, color]) => (
                    <div
                      key={name}
                      style={{
                        borderRadius: 10,
                        padding: '10px 12px',
                        border: '1px solid var(--color-line)',
                        background: 'var(--color-bg)',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          fontSize: 11.5,
                          color: 'var(--color-text-3)',
                        }}
                      >
                        <span
                          style={{
                            width: 8,
                            height: 8,
                            borderRadius: 2,
                            background: color,
                          }}
                        />
                        {name}
                      </div>
                      <div
                        className="mono"
                        style={{ fontSize: 18, marginTop: 4 }}
                      >
                        {compact(value)}
                      </div>
                    </div>
                  ))}
                </div>
                {!canOperate ? (
                  <div style={{ marginTop: 12 }}>
                    <PermissionNote>
                      Switching modes needs the operator role.
                    </PermissionNote>
                  </div>
                ) : null}
              </section>
              {config ? <PolicySettings config={config} /> : null}
            </div>
            <div style={{ flex: '1 1 260px', minWidth: 0 }}>
              <section
                style={{
                  border: '1px solid var(--color-line)',
                  borderRadius: 12,
                  padding: 18,
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <h2 style={{ fontSize: 15, fontWeight: 600 }}>
                    In the config
                  </h2>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      copy(
                        `policy:\n  hosts:\n    ${current.host}: ${current.mode}`,
                        'YAML',
                      );
                    }}
                  >
                    Copy
                  </Button>
                </div>
                <div
                  style={{
                    fontSize: 12.5,
                    color: 'var(--color-text-3)',
                    margin: '4px 0 10px',
                  }}
                >
                  To keep the current mode without the console override:
                </div>
                <pre
                  className={styles.code}
                >{`policy:\n  hosts:\n    ${current.host}: ${current.mode}`}</pre>
              </section>
            </div>
          </div>
        </section>
      ) : null}

      <Dialog
        open={pending !== null}
        onClose={() => {
          setPending(null);
        }}
        label="Confirm mode change"
      >
        {current && pending ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600 }}>
              Switch {current.host} to {pending}?
            </h2>
            <p
              style={{
                fontSize: 13.5,
                color: 'var(--color-text-2)',
                lineHeight: 1.5,
              }}
            >
              {pending === 'enforce'
                ? `Verdicts will be carried out at once. Last hour this would have blocked about ${count(current.would_block)} requests.`
                : pending === 'shadow'
                  ? 'Nothing will be blocked or challenged; verdicts are only logged.'
                  : 'The host will be proxied without verdicts or rate limits.'}{' '}
              The change is a console override and shows in the decision log.
            </p>
            <div
              style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}
            >
              <Button
                variant="ghost"
                onClick={() => {
                  setPending(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant={pending === 'enforce' ? 'danger' : 'primary'}
                onClick={() => {
                  apply(pending);
                }}
              >
                Switch to {pending}
              </Button>
            </div>
          </div>
        ) : null}
      </Dialog>
    </div>
  );
}
