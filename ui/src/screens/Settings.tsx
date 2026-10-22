// Settings: who you are, your session, the theme on this browser, and
// where the rest is configured.

import { useSession } from '../app/session.ts';
import { dateTime } from '../lib/format.ts';
import { useGatewayConfig, useStatus } from '../lib/queries.ts';
import { setTheme, type ThemeChoice, useTheme } from '../lib/theme.ts';
import { Card, PageHead } from '../ui/Card.tsx';
import { Segmented } from '../ui/controls.tsx';
import styles from './screens.module.css';

export function Settings() {
  const session = useSession();
  const { choice } = useTheme();
  const gateway = useStatus().data?.gateway;
  const config = useGatewayConfig().data;
  const rows: [string, string][] = [
    ['User', session.user.name],
    [
      'Role',
      session.user.role === 'operator'
        ? 'operator: can change lists, modes, attack mode and reload'
        : 'viewer: read-only',
    ],
    ['Session ends', dateTime(session.expires_at)],
  ];
  const gatewayRows: [string, string][] = gateway
    ? [
        ['Version', gateway.version],
        ['Workers', String(gateway.workers)],
        [
          'Verdict set',
          `${gateway.generation}${config ? ` · library ${config.library.version}` : ''}`,
        ],
        ['Global mode', gateway.mode],
      ]
    : [];
  return (
    <>
      <PageHead title="Settings" />
      <div className={styles.grid2}>
        <Card title="You">
          <div className={styles.facts} style={{ margin: 16 }}>
            {rows.map(([k, v]) => (
              <div key={k} className={styles.fact}>
                <span className={styles.factKey}>{k}</span>
                <span className="mono" style={{ textAlign: 'right' }}>
                  {v}
                </span>
              </div>
            ))}
          </div>
          <div
            style={{
              padding: '0 16px 16px',
              fontSize: 12.5,
              color: 'var(--color-text-3)',
              lineHeight: 1.5,
            }}
          >
            Users, roles, passwords and two-factor secrets live in the
            console&apos;s <span className="mono">console.yaml</span> (
            <span className="mono">larpguard-console hash-password</span>,{' '}
            <span className="mono">totp-secret</span>). Passkeys are not
            supported yet.
          </div>
        </Card>
        <Card title="Appearance">
          <div
            style={{
              padding: 16,
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
            }}
          >
            <Segmented<ThemeChoice>
              label="Theme"
              mono={false}
              options={[
                { value: 'system', label: 'System' },
                { value: 'dark', label: 'Dark' },
                { value: 'light', label: 'Light' },
              ]}
              value={choice}
              onChange={setTheme}
            />
            <div style={{ fontSize: 12.5, color: 'var(--color-text-3)' }}>
              Kept in this browser only.
            </div>
          </div>
        </Card>
        <Card title="Gateway">
          <div className={styles.facts} style={{ margin: 16 }}>
            {gatewayRows.map(([k, v]) => (
              <div key={k} className={styles.fact}>
                <span className={styles.factKey}>{k}</span>
                <span className="mono">{v}</span>
              </div>
            ))}
            {gatewayRows.length === 0 ? (
              <div className={styles.fact}>
                <span className={styles.factKey}>Admin API</span>
                <span>unreachable</span>
              </div>
            ) : null}
          </div>
        </Card>
      </div>
    </>
  );
}
