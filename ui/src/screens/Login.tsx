// Sign-in: user name and password, then the authenticator code. Both go
// to the server together, so a wrong password is never confirmed on its
// own. Or a passkey, which stands for both. The aside shows what the
// gateway decided about this very request; under the form a connection
// check tells a slow network from a slow server.

import { browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { type SubmitEvent, useRef, useState } from 'react';

import { sessionSchema, whoamiSchema } from '../../shared/api.ts';
import { sessionKey } from '../app/session.ts';
import { ReasonChip } from '../domain/ReasonChip.tsx';
import { ScoreCell } from '../domain/ScoreBar.tsx';
import { ClassBadge } from '../domain/verdict.tsx';
import { ApiError, getJson, sendJson, setCsrfToken } from '../lib/api.ts';
import {
  checkConnection,
  type Diagnosis,
  kHeadline,
} from '../lib/connection.ts';
import { passkeyErrorText, signInWithPasskey } from '../lib/passkeys.ts';
import { useTheme } from '../lib/theme.ts';
import { Button, IconButton } from '../ui/Button.tsx';
import { Eyebrow } from '../ui/Card.tsx';
import { TextInput } from '../ui/controls.tsx';
import { Logo, Spinner } from '../ui/Icon.tsx';
import styles from './Login.module.css';

function useWhoami() {
  return useQuery({
    queryKey: ['whoami'],
    queryFn: ({ signal }) =>
      getJson(whoamiSchema, '/api/whoami', undefined, signal),
    staleTime: Infinity,
  }).data;
}

function Verdict() {
  const whoami = useWhoami();
  const behind = whoami?.score !== null && whoami?.score !== undefined;
  return (
    <aside
      className={styles.aside}
      aria-label="This sign-in as the gateway sees it"
    >
      <Eyebrow>This sign-in, as the gateway sees it</Eyebrow>
      <div className={styles.asideTitle}>
        {behind
          ? "The console sits behind its own gateway. Here's the verdict on you."
          : 'This console is not behind the gateway, so there is no verdict on you.'}
      </div>
      {whoami && behind ? (
        <div className={styles.verdict}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              gap: 12,
            }}
          >
            <div>
              <div className="mono" style={{ fontSize: 13 }}>
                {whoami.ip_prefix ?? 'unknown network'}
              </div>
              {whoami.request_id ? (
                <div
                  className="mono"
                  style={{
                    fontSize: 11.5,
                    color: 'var(--color-text-3)',
                    marginTop: 3,
                  }}
                >
                  {whoami.request_id}
                </div>
              ) : null}
            </div>
            <div style={{ textAlign: 'right' }}>
              <div
                className="mono"
                style={{
                  fontSize: 30,
                  fontWeight: 500,
                  letterSpacing: '-0.03em',
                  lineHeight: 1,
                }}
              >
                {whoami.score}
              </div>
            </div>
          </div>
          <div
            style={{
              margin: '14px 0 12px',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              flexWrap: 'wrap',
            }}
          >
            <ScoreCell score={whoami.score ?? 0} width={180} />
            {whoami.class ? <ClassBadge value={whoami.class} /> : null}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {whoami.reasons.length === 0 ? (
              <span style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                No signals.
              </span>
            ) : (
              whoami.reasons.map((reason) => (
                <ReasonChip key={reason} reason={reason} weight={null} />
              ))
            )}
          </div>
        </div>
      ) : null}
      <div className={styles.asideNote}>
        Five failed sign-ins for a user name or from one network lock it for
        five minutes. Every attempt is written to the decision log.
      </div>
    </aside>
  );
}

function msText(value: number | null): string {
  if (value === null) return '–';
  return value < 1 ? '<1 ms' : `${Math.round(value)} ms`;
}

function CheckRows({ diagnosis }: { diagnosis: Diagnosis }) {
  const rows: [string, string][] = [
    [
      'Network',
      diagnosis.network_ms === null
        ? 'no answer'
        : `${msText(diagnosis.network_ms)} (${msText(diagnosis.fastest_ms)}–${msText(diagnosis.slowest_ms)})`,
    ],
    ['Answered', `${diagnosis.sent - diagnosis.lost} of ${diagnosis.sent}`],
    ['Console', msText(diagnosis.server_ms)],
    [
      'Gateway',
      diagnosis.gateway_ms === undefined
        ? '–'
        : diagnosis.gateway_ms === null
          ? 'no answer'
          : msText(diagnosis.gateway_ms),
    ],
  ];
  return (
    <dl className={styles.checkRows}>
      {rows.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd className="mono">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

// "Is it me or the server": timed calls to the console, split into the
// network's share and the server's.
function ConnectionCheck() {
  const check = useQuery({
    queryKey: ['connection-check'],
    queryFn: ({ signal }) => checkConnection(signal),
    staleTime: Infinity,
    retry: false,
  });
  const relayed = useWhoami()?.reasons.includes('relayed_connection') === true;
  const diagnosis = check.data;
  const tone = check.isFetching
    ? 'pending'
    : diagnosis?.culprit === 'none'
      ? 'ok'
      : 'bad';
  return (
    <section className={styles.check} aria-label="Connection check">
      <div className={styles.checkHead}>
        <span className={styles.checkDot} data-tone={tone} aria-hidden="true" />
        <span role="status" className={styles.checkTitle}>
          {check.isFetching || !diagnosis
            ? 'Checking your connection to the console…'
            : kHeadline[diagnosis.culprit]}
        </span>
        <button
          type="button"
          className={styles.link}
          disabled={check.isFetching}
          onClick={() => void check.refetch()}
        >
          Check again
        </button>
      </div>
      {diagnosis && !check.isFetching ? (
        <>
          <CheckRows diagnosis={diagnosis} />
          {diagnosis.findings.length > 0 || relayed ? (
            <ul className={styles.checkFindings}>
              {diagnosis.findings.map((finding) => (
                <li key={finding}>{finding}</li>
              ))}
              {relayed ? (
                <li>
                  The gateway sees your connection relayed: a VPN or proxy sits
                  between you and it, which adds its own delay.
                </li>
              ) : null}
            </ul>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

export function Login() {
  const client = useQueryClient();
  const { theme, toggle } = useTheme();
  const [step, setStep] = useState<'password' | 'code'>('password');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);
  const passkeys = useWhoami()?.passkeys === true && browserSupportsWebAuthn();

  const withPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      const session = await signInWithPasskey();
      setCsrfToken(session.csrf);
      client.setQueryData(sessionKey, session);
    } catch (failure) {
      setError(
        passkeyErrorText(failure) ??
          (failure instanceof ApiError
            ? failure.status === 401
              ? 'This passkey was not accepted. Use your password and code.'
              : failure.message
            : 'Passkey sign-in failed.'),
      );
    } finally {
      setBusy(false);
    }
  };

  const toCode = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!username || !password) {
      setError('Enter your user name and password.');
      return;
    }
    setError(null);
    setStep('code');
    setTimeout(() => codeRef.current?.focus(), 0);
  };

  // `typed`: the code as just entered (state lags one render behind).
  const submit = async (
    event?: SubmitEvent<HTMLFormElement>,
    typed: string = code,
  ) => {
    event?.preventDefault();
    if (busy) return;
    if (!/^\d{6}$/.test(typed)) {
      setError('Enter the six digits from your authenticator.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const session = await sendJson(sessionSchema, 'POST', '/api/session', {
        username,
        password,
        totp: typed,
      });
      setCsrfToken(session.csrf);
      setPassword('');
      client.setQueryData(sessionKey, session);
    } catch (failure) {
      setCode('');
      setError(
        failure instanceof ApiError
          ? failure.status === 401
            ? 'The user name, password or code is wrong. Check them and try a fresh code.'
            : failure.message
          : 'Sign-in failed.',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <div className={styles.top}>
          <Logo size={24} />
          <span style={{ fontWeight: 600, fontSize: 15 }}>LarpGuard</span>
          <span style={{ marginLeft: 'auto' }}>
            <IconButton
              icon={theme === 'dark' ? 'moon' : 'sun'}
              label="Toggle theme"
              onClick={toggle}
            />
          </span>
        </div>
        <div className={styles.center}>
          <div className={styles.form}>
            <ol
              className={styles.steps}
              aria-label="Sign-in steps"
              style={{ listStyle: 'none', padding: 0, margin: '0 0 28px' }}
            >
              <li
                className={`${styles.step} ${step === 'code' ? styles.done : ''}`}
                aria-current={step === 'password' ? 'step' : undefined}
              >
                Password
              </li>
              <li
                className={styles.step}
                aria-current={step === 'code' ? 'step' : undefined}
              >
                Two-factor
              </li>
            </ol>

            {step === 'password' ? (
              <form onSubmit={toCode} noValidate>
                <h1 className={styles.title}>Sign in to the console</h1>
                <p className={styles.lead}>
                  Admin access to this gateway. Sessions expire after 12 hours.
                </p>
                <div className={styles.fields}>
                  <TextInput
                    label="Username"
                    autoComplete="username"
                    mono
                    value={username}
                    onChange={(event) => {
                      setUsername(event.target.value.trim());
                    }}
                    style={{ height: 42 }}
                  />
                  <TextInput
                    label={
                      <span
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                        }}
                      >
                        Password
                      </span>
                    }
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    mono
                    value={password}
                    onChange={(event) => {
                      setPassword(event.target.value);
                    }}
                    style={{ height: 42 }}
                    error={error ?? undefined}
                  />
                  <button
                    type="button"
                    className={styles.link}
                    style={{
                      alignSelf: 'flex-end',
                      marginTop: -6,
                      fontSize: 12,
                    }}
                    onClick={() => {
                      setShowPassword((show) => !show);
                    }}
                  >
                    {showPassword ? 'Hide password' : 'Show password'}
                  </button>
                  <Button type="submit" variant="primary" size="lg" block>
                    Continue
                  </Button>
                  {passkeys ? (
                    <Button
                      size="lg"
                      block
                      disabled={busy}
                      onClick={() => void withPasskey()}
                    >
                      {busy ? <Spinner /> : null}
                      Sign in with a passkey
                    </Button>
                  ) : null}
                </div>
                <p className={styles.foot}>
                  Lost access? An administrator sets a new hash with{' '}
                  <span
                    className="mono"
                    style={{ color: 'var(--color-text-2)' }}
                  >
                    larpguard-console hash-password
                  </span>{' '}
                  in <span className="mono">console.yaml</span>.
                </p>
              </form>
            ) : (
              <form onSubmit={(event) => void submit(event)} noValidate>
                <h1 className={styles.title}>Two-factor check</h1>
                <p className={styles.lead}>
                  Enter the 6-digit code from your authenticator for{' '}
                  <span className="mono" style={{ color: 'var(--color-text)' }}>
                    {username}
                  </span>
                  .
                </p>
                <label
                  htmlFor="lg-totp"
                  style={{
                    display: 'block',
                    fontSize: 12.5,
                    color: 'var(--color-text-2)',
                    marginBottom: 8,
                  }}
                >
                  Code
                </label>
                <div className={styles.boxes}>
                  <div className={styles.boxRow} aria-hidden="true">
                    {Array.from({ length: 6 }, (_, i) => (
                      <div
                        // biome-ignore lint/suspicious/noArrayIndexKey: one box per code digit.
                        key={i}
                        className={`mono ${styles.box} ${error ? styles.boxError : i === code.length ? styles.boxActive : ''}`}
                      >
                        {code[i] ?? ''}
                      </div>
                    ))}
                  </div>
                  <input
                    id="lg-totp"
                    ref={codeRef}
                    className={styles.codeInput}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={code}
                    aria-invalid={error ? true : undefined}
                    onChange={(event) => {
                      const digits = event.target.value
                        .replace(/\D/g, '')
                        .slice(0, 6);
                      setCode(digits);
                      setError(null);
                      // The sixth digit signs in, no Verify press needed.
                      if (digits.length === 6 && code.length < 6) {
                        void submit(undefined, digits);
                      }
                    }}
                  />
                </div>
                {error ? (
                  <div
                    role="alert"
                    style={{
                      marginTop: 10,
                      fontSize: 12.5,
                      color: 'var(--color-blocked-text)',
                    }}
                  >
                    {error}
                  </div>
                ) : null}
                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  block
                  disabled={busy}
                  style={{ marginTop: 18 }}
                >
                  {busy ? <Spinner /> : null}
                  Verify
                </Button>
                <div className={styles.row}>
                  <span style={{ color: 'var(--color-text-3)' }}>
                    Codes change every 30 seconds.
                  </span>
                  <button
                    type="button"
                    className={styles.link}
                    onClick={() => {
                      setStep('password');
                      setCode('');
                      setError(null);
                    }}
                  >
                    Back
                  </button>
                </div>
              </form>
            )}
            <ConnectionCheck />
          </div>
        </div>
      </main>
      <Verdict />
    </div>
  );
}
