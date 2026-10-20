// Stroke icons from the design (16×16 grid, currentColor).

import { ICON_PATHS, type IconName } from './icons.ts';

export function Icon({
  name,
  size = 16,
  strokeWidth = 1.3,
  className,
}: {
  name: IconName;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
      className={className}
      style={{ flex: 'none' }}
    >
      <path
        d={ICON_PATHS[name]}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// The LarpGuard mark: an L in a rounded square with the orange dot.
export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" aria-hidden="true">
      <rect
        x="1"
        y="1"
        width="26"
        height="26"
        rx="7"
        fill="none"
        stroke="var(--color-text)"
        strokeWidth="1.6"
      />
      <path
        d="M8 9v10h6"
        fill="none"
        stroke="var(--color-text)"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <circle cx="19" cy="16" r="3" fill="var(--color-blocked)" />
    </svg>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
      style={{ animation: 'spin 0.9s linear infinite', flex: 'none' }}
    >
      <circle
        cx="8"
        cy="8"
        r="6"
        fill="none"
        stroke="var(--color-line-strong)"
        strokeWidth="1.6"
      />
      <path
        d="M8 2a6 6 0 0 1 6 6"
        fill="none"
        stroke="var(--color-text)"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}
