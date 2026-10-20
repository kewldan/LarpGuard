// Form controls: segmented, switch, text fields, query bar.

import {
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';

import styles from './controls.module.css';
import { Icon } from './Icon.tsx';

export function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
  fill = false,
  mono = true,
}: {
  label: string;
  options: readonly (T | { value: T; label: ReactNode })[];
  value: T;
  onChange: (value: T) => void;
  fill?: boolean;
  mono?: boolean;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className={`${styles.segmented} ${fill ? styles.fill : ''}`}
    >
      {options.map((option) => {
        const item =
          typeof option === 'string'
            ? { value: option, label: option }
            : option;
        return (
          <button
            key={item.value}
            type="button"
            aria-pressed={item.value === value}
            className={`${styles.segment} ${mono ? 'mono' : ''}`}
            onClick={() => {
              onChange(item.value);
            }}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}

export function Switch({
  checked,
  onChange,
  children,
  danger = false,
  disabled = false,
  label,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  children?: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className={`${styles.switch} ${danger ? styles.danger : ''}`}
      onClick={() => {
        onChange(!checked);
      }}
    >
      <span className={styles.track}>
        <span className={styles.thumb} />
      </span>
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  id,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
  id: string;
}) {
  return (
    <div className={styles.field}>
      <label htmlFor={id} className={styles.label}>
        {label}
      </label>
      {children}
      {error ? (
        <div role="alert" className={styles.error}>
          {error}
        </div>
      ) : hint ? (
        <div className={styles.hint}>{hint}</div>
      ) : null}
    </div>
  );
}

export function TextInput({
  label,
  hint,
  error,
  mono = false,
  className,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  mono?: boolean;
}) {
  const id = useId();
  return (
    <Field label={label} hint={hint} error={error} id={id}>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        className={`${styles.input} ${mono ? 'mono' : ''} ${className ?? ''}`}
        {...rest}
      />
    </Field>
  );
}

export function TextArea({
  label,
  hint,
  error,
  className,
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement> & {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
}) {
  const id = useId();
  return (
    <Field label={label} hint={hint} error={error} id={id}>
      <textarea
        id={id}
        aria-invalid={error ? true : undefined}
        spellCheck={false}
        className={`${styles.input} ${styles.textarea} mono ${className ?? ''}`}
        {...rest}
      />
    </Field>
  );
}

export function Select({
  label,
  children,
  className,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { label: ReactNode }) {
  const id = useId();
  return (
    <Field label={label} id={id}>
      <select
        id={id}
        className={`${styles.input} ${styles.select} ${className ?? ''}`}
        {...rest}
      >
        {children}
      </select>
    </Field>
  );
}

export function QueryBar({
  label,
  hint,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  return (
    <div className={styles.queryBar}>
      <Icon name="search" size={14} strokeWidth={1.4} />
      <input aria-label={label} className="mono" spellCheck={false} {...rest} />
      {hint ? <span className={styles.kbd}>{hint}</span> : null}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <span className={styles.kbd}>{children}</span>;
}
