// Empty, loading and error states ("Empty, loading & error states" board):
// every failure says whether traffic is still being filtered and gives a
// next step.

import { useEffect, useState, type CSSProperties, type ReactNode } from 'react';

import { Button } from './Button.tsx';
import { Icon } from './Icon.tsx';
import styles from './states.module.css';

// Mounted while loading; shows its children only after 300 ms, so fast
// queries just appear.
function Delayed({ children, ms = 300 }: { children: ReactNode; ms?: number }) {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => {
      setShown(true);
    }, ms);
    return () => {
      clearTimeout(timer);
    };
  }, [ms]);
  return shown ? children : null;
}

export function Shimmer({ style }: { style?: CSSProperties }) {
  return <span className={styles.shim} style={{ height: 10, ...style }} />;
}

export function Skeleton({
  loading,
  rows = 4,
  label = 'Loading',
}: {
  loading: boolean;
  rows?: number;
  label?: string;
}) {
  if (!loading) return null;
  return (
    <Delayed>
      <div
        role="status"
        aria-label={label}
        style={{ padding: 16, display: 'grid', gap: 12 }}
      >
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} style={{ display: 'flex', gap: 12 }}>
            <Shimmer style={{ width: 70 }} />
            <Shimmer style={{ flex: 1 }} />
          </div>
        ))}
      </div>
    </Delayed>
  );
}

export function EmptyState({
  title,
  children,
  actions,
}: {
  title: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className={styles.empty}>
      <div className={styles.emptyTitle}>{title}</div>
      {children ? <div className={styles.emptyText}>{children}</div> : null}
      {actions ? <div className={styles.actions}>{actions}</div> : null}
    </div>
  );
}

// Analytics unavailable: amber, because the gateway still filters.
export function AnalyticsBanner({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div role="status" className={styles.degraded}>
      <span
        className={styles.dot}
        style={{ background: 'var(--color-challenged)' }}
      />
      <span style={{ flex: '1 1 260px' }}>
        <b>Analytics paused.</b> Traffic is still being filtered. {message}
      </span>
      {onRetry ? (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

// The gateway is unreachable: inverted, the loudest state.
export function GatewayDown({ detail }: { detail: string }) {
  return (
    <div role="alert" className={styles.down}>
      <div className={styles.downTitle}>
        <span className={styles.downMark}>!</span>Gateway not responding
      </div>
      <div style={{ fontSize: 13.5, lineHeight: 1.5 }}>
        {detail} If the gateway is down, the fail-open watchdog sends new
        connections straight to Traefik: traffic may be passing unfiltered.
      </div>
      <code className={`mono ${styles.code}`}>
        systemctl status bot-shield{'\n'}journalctl -u bot-shield -n 50
        --no-pager
      </code>
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  return (
    <div role="alert" className={styles.errorState}>
      <span
        className={styles.dot}
        style={{ background: 'var(--color-challenged)' }}
      />
      <span style={{ flex: '1 1 240px' }}>
        {error instanceof Error ? error.message : 'Something went wrong.'}
      </span>
      {onRetry ? (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

// In place of an action the viewer role cannot take.
export function PermissionNote({ children }: { children: ReactNode }) {
  return (
    <div className={styles.note}>
      <Icon name="settings" size={16} />
      <div>
        <div style={{ color: 'var(--color-text)', fontWeight: 600 }}>
          Only operators can change this
        </div>
        <div>{children}</div>
      </div>
    </div>
  );
}
