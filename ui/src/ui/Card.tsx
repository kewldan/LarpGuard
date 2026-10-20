import type { HTMLAttributes, ReactNode } from 'react';

import styles from './Card.module.css';

// A bordered panel; with `title` it gets a header row.
export function Card({
  title,
  aside,
  plain = false,
  flush = false,
  children,
  className,
  ...rest
}: Omit<HTMLAttributes<HTMLElement>, 'title'> & {
  title?: ReactNode;
  aside?: ReactNode;
  plain?: boolean;
  flush?: boolean;
  children: ReactNode;
}) {
  return (
    <section
      className={[
        styles.card,
        plain ? styles.plain : '',
        flush || title ? styles.flush : '',
        className ?? '',
      ].join(' ')}
      {...rest}
    >
      {title ? (
        <div className={styles.head}>
          <h2 className={styles.title}>{title}</h2>
          {aside ? <div className={styles.aside}>{aside}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function CardBody({ children }: { children: ReactNode }) {
  return <div className={styles.body}>{children}</div>;
}

export function Eyebrow({ children }: { children: ReactNode }) {
  return <div className={styles.eyebrow}>{children}</div>;
}

export function PageHead({
  title,
  sub,
  children,
}: {
  title: ReactNode;
  sub?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className={styles.pageHead}>
      <div>
        <h1 className={styles.pageTitle}>{title}</h1>
        {sub ? <div className={styles.pageSub}>{sub}</div> : null}
      </div>
      {children}
    </div>
  );
}
