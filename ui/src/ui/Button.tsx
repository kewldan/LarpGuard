import type { ButtonHTMLAttributes, ReactNode } from 'react';

import styles from './Button.module.css';
import { Icon } from './Icon.tsx';
import type { IconName } from './icons.ts';

export type ButtonVariant =
  'primary' | 'secondary' | 'ghost' | 'danger' | 'dangerOutline';

export function Button({
  variant = 'secondary',
  size = 'md',
  block = false,
  className,
  children,
  type = 'button',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  block?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      type={type}
      className={[
        styles.button,
        styles[variant],
        size === 'md' ? '' : styles[size],
        block ? styles.block : '',
        className ?? '',
      ].join(' ')}
      {...rest}
    >
      {children}
    </button>
  );
}

// Icon-only: needs a label for assistive tech.
export function IconButton({
  icon,
  label,
  bare = false,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: IconName;
  label: string;
  bare?: boolean;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={[
        styles.button,
        bare ? styles.iconBare : styles.icon,
        className ?? '',
      ].join(' ')}
      {...rest}
    >
      <Icon name={icon} size={bare ? 18 : 14} strokeWidth={1.5} />
    </button>
  );
}
