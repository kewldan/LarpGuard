// Short confirmations ("Copied", "Added to block list").

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import { ToastContext } from './toast-context.ts';

export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const show = useCallback((text: string) => {
    setMessage(text);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      setMessage(null);
    }, 2400);
  }, []);
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );
  return (
    <ToastContext value={show}>
      {children}
      <div
        role="status"
        aria-live="polite"
        className="mono"
        style={{
          position: 'fixed',
          left: '50%',
          bottom: 24,
          zIndex: 'var(--z-toast)',
          transform: `translate(-50%, ${message ? 0 : 10}px)`,
          opacity: message ? 1 : 0,
          pointerEvents: 'none',
          transition: `opacity var(--duration-${message ? 'base' : 'exit'}) var(--ease-${message ? 'out' : 'in'}), transform var(--duration-${message ? 'base' : 'exit'}) var(--ease-${message ? 'out' : 'in'})`,
          maxWidth: 'calc(100vw - 32px)',
          padding: '10px 14px',
          borderRadius: 'var(--radius-card)',
          background: 'var(--color-inverse)',
          color: 'var(--color-on-inverse)',
          fontSize: 12.5,
          boxShadow: 'var(--shadow-fab)',
        }}
      >
        {message}
      </div>
    </ToastContext>
  );
}
