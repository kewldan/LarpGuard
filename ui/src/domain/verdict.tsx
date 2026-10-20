// Action chips, client classes and host modes ("03 Actions, classes,
// modes"): seven actions fold into three tones; filled is terminal, soft
// is friction, dashed is degraded but passing.

import { ACTION_LOOK, isAction, type HostMode } from '../../shared/domain.ts';
import styles from './verdict.module.css';

function actionClass(action: string): string {
  if (!isAction(action)) return styles.neutral ?? '';
  const look = ACTION_LOOK[action];
  if (action === 'block') return styles.block ?? '';
  if (action === 'decoy') return styles.decoy ?? '';
  if (look.style === 'outline') return styles.degrade ?? '';
  return (look.tone === 'challenged' ? styles.challenge : styles.allow) ?? '';
}

export function ActionChip({
  action,
  small = false,
  dot = !small,
}: {
  action: string;
  small?: boolean;
  dot?: boolean;
}) {
  return (
    <span
      className={`${styles.chip} ${small ? styles.small : ''} ${actionClass(action || 'allow')}`}
    >
      {dot ? <span className={styles.dot} /> : null}
      {action || 'allow'}
    </span>
  );
}

const CLASS_ICON: Record<string, string> = {
  human: 'M5 4.5a1.5 1.5 0 1 0 0-.01M2 9c.5-2 1.6-3 3-3s2.5 1 3 3',
  verified_bot: 'M2 5.2l2 2L8 3',
  bot: 'M2.5 2.5l5 5M7.5 2.5l-5 5',
  suspicious: 'M3.5 3.5a1.6 1.6 0 1 1 2.2 1.5c-.5.2-.7.6-.7 1M5 8v.01',
};

export function ClassBadge({ value }: { value: string }) {
  const known = value in CLASS_ICON;
  return (
    <span
      className={`${styles.class} ${known ? (styles[value] ?? '') : styles.suspicious}`}
    >
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
        <path
          d={CLASS_ICON[value] ?? CLASS_ICON.suspicious}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {value || 'unscored'}
    </span>
  );
}

// SHADOW is a hatch with a dashed edge, ENFORCE is filled.
export function ModeBadge({
  mode,
  large = false,
}: {
  mode: HostMode;
  large?: boolean;
}) {
  const kind =
    mode === 'shadow'
      ? `${styles.shadowMode} hatch`
      : mode === 'enforce'
        ? styles.enforceMode
        : styles.offMode;
  return (
    <span className={`${styles.mode} ${large ? styles.large : ''} ${kind}`}>
      {large ? (
        <span
          className={`${styles.modeSwatch} ${mode === 'shadow' ? 'hatch' : ''}`}
        />
      ) : null}
      {mode.toUpperCase()}
    </span>
  );
}
