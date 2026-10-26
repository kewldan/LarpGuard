// The frame around every screen: sidebar, top bar with the palette and the
// attack pill; on phones a header and a tab bar instead.

import { useQueryClient } from '@tanstack/react-query';
import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { HealthDot, type HealthState } from '../domain/charts.tsx';
import { send } from '../lib/api.ts';
import { ago, compact } from '../lib/format.ts';
import { useGatewayConfig, useStatus } from '../lib/queries.ts';
import { useTheme } from '../lib/theme.ts';
import { IconButton } from '../ui/Button.tsx';
import { Kbd } from '../ui/controls.tsx';
import { Icon, Logo } from '../ui/Icon.tsx';
import { Dialog } from '../ui/Overlay.tsx';
import { CommandPalette } from './CommandPalette.tsx';
import { NAV } from './nav.ts';
import styles from './Shell.module.css';
import { sessionKey, useSession } from './session.ts';

function useSignOut(): () => void {
  const client = useQueryClient();
  return () => {
    void send('DELETE', '/api/session').finally(() => {
      // Null first, then drop the rest: clear() would also remove the
      // session query its observer watches, and the screen would not
      // notice the sign-out.
      client.setQueryData(sessionKey, null);
      client.removeQueries({
        predicate: (query) => query.queryKey[0] !== sessionKey[0],
      });
    });
  };
}

function overallHealth(status: ReturnType<typeof useStatus>['data']): {
  state: HealthState;
  text: string;
} {
  if (!status) return { state: 'off', text: 'Checking…' };
  const { health } = status;
  if (health.admin === 'down' || health.workers === 'down') {
    return { state: 'down', text: 'Gateway not responding' };
  }
  if (health.workers === 'degraded')
    return { state: 'degraded', text: 'A worker stalled' };
  if (health.clickhouse === 'down' || health.events === 'down') {
    return { state: 'degraded', text: 'Analytics degraded' };
  }
  if (health.clickhouse === 'degraded')
    return { state: 'degraded', text: 'ClickHouse lagging' };
  return { state: 'ok', text: 'All systems nominal' };
}

function AttackPill({ phone = false }: { phone?: boolean }) {
  const status = useStatus().data;
  const config = useGatewayConfig().data;
  const on = (status?.gateway?.attack_entries ?? 0) > 0;
  const auto = config?.attack.auto_rps ?? 0;
  return (
    <Link
      to="/attack"
      className={`${styles.attackPill} ${on ? styles.attackOn : ''}`}
    >
      <span className={styles.pillDot} />
      {phone ? (
        on ? (
          'Attack on'
        ) : (
          'Attack off'
        )
      ) : (
        <>
          Attack mode <b style={{ fontWeight: 600 }}>{on ? 'on' : 'off'}</b>
          {!on && auto > 0 ? (
            <span className={styles.pillMeta}>
              · auto at {compact(auto)} rps per host
            </span>
          ) : null}
        </>
      )}
    </Link>
  );
}

function ThemeButton({ bare = false }: { bare?: boolean }) {
  const { theme, toggle } = useTheme();
  return (
    <IconButton
      icon={theme === 'dark' ? 'moon' : 'sun'}
      label={
        theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
      }
      bare={bare}
      onClick={toggle}
    />
  );
}

export function Shell() {
  const session = useSession();
  const status = useStatus().data;
  const signOut = useSignOut();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });
  const current = NAV.find((item) =>
    item.to === '/' ? pathname === '/' : pathname.startsWith(item.to),
  );
  const health = overallHealth(status);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, []);

  useEffect(() => {
    document.title = current ? `${current.name} · LarpGuard` : 'LarpGuard';
  }, [current]);

  const gateway = status?.gateway;
  return (
    <div className={styles.app}>
      <a href="#main" className="visually-hidden">
        Skip to content
      </a>
      <aside className={styles.side} aria-label="Sidebar">
        <div className={styles.brand}>
          <Logo />
          <span className={styles.brandName}>LarpGuard</span>
          {gateway ? (
            <span className={`mono ${styles.version}`}>v{gateway.version}</span>
          ) : null}
        </div>
        <nav className={styles.nav} aria-label="Main">
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className={styles.navLink}
              activeOptions={{ exact: item.to === '/' }}
            >
              <Icon name={item.icon} />
              {item.name}
              {item.to === '/lists' && gateway ? (
                <span className={`mono ${styles.badge}`}>
                  {gateway.list_entries}
                </span>
              ) : null}
            </Link>
          ))}
        </nav>
        <div className={styles.foot}>
          <div className={styles.footLine}>
            <HealthDot state={health.state} size={7} />
            {health.text}
          </div>
          {gateway ? (
            <div
              className={`mono ${styles.footMeta}`}
              title={`Configuration hash ${gateway.config_hash}, verdict set ${gateway.generation}`}
            >
              config {gateway.config_hash.slice(0, 6)}
              {gateway.built_at_ms
                ? ` · loaded ${ago(gateway.built_at_ms)}`
                : ''}
            </div>
          ) : null}
          <div className={styles.footUser}>
            <span
              className="mono"
              style={{ fontSize: 11.5, color: 'var(--color-text-2)' }}
            >
              {session.user.name}
            </span>
            <span style={{ display: 'flex', gap: 10 }}>
              <Link to="/settings">Settings</Link>
              <button type="button" onClick={signOut}>
                Sign out
              </button>
            </span>
          </div>
        </div>
      </aside>

      <div className={styles.column}>
        <header className={styles.header}>
          <button
            type="button"
            className={styles.paletteButton}
            onClick={() => {
              setPaletteOpen(true);
            }}
          >
            <Icon name="search" size={14} strokeWidth={1.4} />
            <span style={{ flex: 1 }}>Jump to IP hash, JA4, host, rule…</span>
            <Kbd>⌘K</Kbd>
          </button>
          <div className={styles.spacer} />
          <AttackPill />
          <ThemeButton />
        </header>

        <header className={styles.phoneHeader}>
          <Logo />
          <span className={styles.phoneTitle}>
            {current?.name ?? 'LarpGuard'}
          </span>
          <AttackPill phone />
          <ThemeButton bare />
          <IconButton
            icon="menu"
            label="All screens"
            bare
            onClick={() => {
              setMenuOpen(true);
            }}
          />
        </header>

        <main id="main" className={styles.main}>
          <Outlet />
        </main>

        <nav className={styles.tabs} aria-label="Main">
          {NAV.filter((item) => item.tab).map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className={styles.tab}
              activeOptions={{ exact: item.to === '/' }}
            >
              <Icon name={item.icon} size={20} />
              {item.tab}
            </Link>
          ))}
        </nav>
      </div>

      <CommandPalette
        open={paletteOpen}
        onClose={() => {
          setPaletteOpen(false);
        }}
      />
      <Dialog
        open={menuOpen}
        onClose={() => {
          setMenuOpen(false);
        }}
        label="All screens"
        variant="sheet"
      >
        {/* biome-ignore lint/a11y/useKeyWithClickEvents: delegates clicks of the links inside, which handle the keyboard. */}
        <nav
          className={styles.menuList}
          aria-label="All screens"
          onClick={(event) => {
            // Any link closes the sheet.
            if ((event.target as HTMLElement).closest('a')) setMenuOpen(false);
          }}
        >
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className={styles.navLink}
              activeOptions={{ exact: item.to === '/' }}
            >
              <Icon name={item.icon} />
              {item.name}
            </Link>
          ))}
          <Link to="/settings" className={styles.navLink}>
            <Icon name="settings" />
            Settings
          </Link>
          <button
            type="button"
            className={styles.navLink}
            style={{ border: 0, background: 'transparent', textAlign: 'left' }}
            onClick={signOut}
          >
            <Icon name="signOut" />
            Sign out
          </button>
        </nav>
      </Dialog>
    </div>
  );
}
