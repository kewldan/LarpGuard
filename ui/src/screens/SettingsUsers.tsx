// Settings → Users (admins): who can sign in. Users from console.yaml are
// read-only here; the rest an admin adds, re-roles, resets and removes,
// each time confirming with their own password and a fresh code. New
// credentials are shown once.

import { type SubmitEvent, useState } from 'react';

import type { UserCredentials, UserList } from '../../shared/api.ts';
import { ROLES, type Role } from '../../shared/domain.ts';
import { useSession } from '../app/session.ts';
import { ApiError } from '../lib/api.ts';
import { ago } from '../lib/format.ts';
import { useUserChange, useUsers } from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { Select, TextInput } from '../ui/controls.tsx';
import { Spinner } from '../ui/Icon.tsx';
import { Dialog } from '../ui/Overlay.tsx';
import { useCopy, useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

type User = UserList['users'][number];
type Pending =
  | { kind: 'add' }
  | { kind: 'role'; user: User; role: Role }
  | { kind: 'reset'; user: User }
  | { kind: 'remove'; user: User };

const note = {
  padding: '0 16px 16px',
  fontSize: 12.5,
  color: 'var(--color-text-3)',
  lineHeight: 1.5,
} as const;

function title(pending: Pending): string {
  switch (pending.kind) {
    case 'add':
      return 'Add a user';
    case 'role':
      return `Make ${pending.user.name} ${pending.role}`;
    case 'reset':
      return `New password and code for ${pending.user.name}`;
    case 'remove':
      return `Remove ${pending.user.name}`;
  }
}

function Confirm({
  pending,
  onDone,
  onClose,
}: {
  pending: Pending;
  onDone: (credentials: UserCredentials | null) => void;
  onClose: () => void;
}) {
  const change = useUserChange();
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (pending.kind === 'add' && !/^[A-Za-z0-9._-]{1,64}$/.test(name)) {
      setError('A name of letters, digits, ".", "-" and "_".');
      return;
    }
    if (!password || !/^\d{6}$/.test(code)) {
      setError('Enter your password and a fresh code.');
      return;
    }
    setError(null);
    const confirm = { password, totp: code };
    change.mutate(
      pending.kind === 'add'
        ? { kind: 'add', name, role, confirm }
        : pending.kind === 'role'
          ? {
              kind: 'role',
              name: pending.user.name,
              role: pending.role,
              confirm,
            }
          : { kind: pending.kind, name: pending.user.name, confirm },
      {
        onSuccess: onDone,
        onError: (failure) => {
          setCode('');
          setError(
            failure instanceof ApiError || failure instanceof Error
              ? failure.message
              : 'Something went wrong.',
          );
        },
      },
    );
  };

  return (
    <form
      onSubmit={submit}
      noValidate
      style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
    >
      <h2 style={{ fontSize: 18, fontWeight: 600 }}>{title(pending)}</h2>
      {pending.kind === 'add' ? (
        <>
          <TextInput
            label="User name"
            mono
            maxLength={64}
            value={name}
            onChange={(event) => {
              setName(event.target.value.trim());
            }}
          />
          <Select
            label="Role"
            value={role}
            onChange={(event) => {
              setRole(event.target.value as Role);
            }}
          >
            {ROLES.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </Select>
        </>
      ) : (
        <p style={{ fontSize: 13.5, color: 'var(--color-text-2)' }}>
          {pending.kind === 'remove'
            ? 'Their sessions end and their passkeys are removed.'
            : pending.kind === 'reset'
              ? 'The old password, code and passkeys stop working; their sessions end.'
              : 'Their sessions end; they sign in again with the new role.'}
        </p>
      )}
      <TextInput
        label="Your password"
        type="password"
        autoComplete="current-password"
        mono
        value={password}
        onChange={(event) => {
          setPassword(event.target.value);
        }}
      />
      <TextInput
        label="Your code"
        inputMode="numeric"
        autoComplete="one-time-code"
        mono
        maxLength={6}
        value={code}
        onChange={(event) => {
          setCode(event.target.value.replace(/\D/g, '').slice(0, 6));
        }}
        error={error ?? undefined}
      />
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant={pending.kind === 'remove' ? 'danger' : 'primary'}
          disabled={change.isPending}
        >
          {change.isPending ? <Spinner /> : null}
          {pending.kind === 'remove' ? 'Remove' : 'Confirm'}
        </Button>
      </div>
    </form>
  );
}

function Shown({
  credentials,
  onClose,
}: {
  credentials: UserCredentials;
  onClose: () => void;
}) {
  const copy = useCopy();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <h2 style={{ fontSize: 18, fontWeight: 600 }}>
        Credentials for {credentials.name}
      </h2>
      <p style={{ fontSize: 13.5, color: 'var(--color-text-2)' }}>
        Shown only now: the console keeps the password&apos;s hash. Hand them
        over privately; the authenticator app takes the secret or the link.
      </p>
      <div className={styles.facts}>
        {(
          [
            ['Password', credentials.password],
            ['TOTP secret', credentials.totp_secret],
            ['otpauth link', credentials.otpauth],
          ] as const
        ).map(([k, v]) => (
          <div key={k} className={styles.fact}>
            <span className={styles.factKey}>{k}</span>
            <span
              className="mono"
              style={{ overflowWrap: 'anywhere', textAlign: 'right' }}
            >
              {v}
            </span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                copy(v, k);
              }}
            >
              Copy
            </Button>
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      </div>
    </div>
  );
}

export function UsersCard() {
  const session = useSession();
  const users = useUsers(true);
  const toast = useToast();
  const [pending, setPending] = useState<Pending | null>(null);
  const [shown, setShown] = useState<UserCredentials | null>(null);
  const data = users.data;

  return (
    <Card
      title="Users"
      aria-label="Users"
      aside={
        data?.editable ? (
          <Button
            size="sm"
            onClick={() => {
              setPending({ kind: 'add' });
            }}
          >
            Add user
          </Button>
        ) : null
      }
    >
      <div className={styles.facts} style={{ margin: 16 }}>
        {(data?.users ?? []).map((user) => {
          const own = user.name === session.user.name;
          const managed = user.source === 'console';
          return (
            <div
              key={user.name}
              className={styles.fact}
              style={{ alignItems: 'center', flexWrap: 'wrap', gap: 8 }}
            >
              <div style={{ minWidth: 0, flex: '1 1 160px' }}>
                <div className="mono" style={{ fontWeight: 500 }}>
                  {user.name}
                  {own ? ' (you)' : ''}
                </div>
                <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                  {managed
                    ? `added ${user.created_at ? ago(user.created_at) : ''} by ${user.created_by ?? '?'}`
                    : 'console.yaml'}{' '}
                  · {user.passkeys} passkeys · {user.sessions} sessions
                </div>
              </div>
              {managed && !own ? (
                <>
                  <select
                    aria-label={`Role of ${user.name}`}
                    className="mono"
                    value={user.role}
                    onChange={(event) => {
                      setPending({
                        kind: 'role',
                        user,
                        role: event.target.value as Role,
                      });
                    }}
                    style={{
                      height: 28,
                      borderRadius: 6,
                      border: '1px solid var(--color-line-strong)',
                      background: 'var(--color-surface-1)',
                    }}
                  >
                    {ROLES.map((role) => (
                      <option key={role} value={role}>
                        {role}
                      </option>
                    ))}
                  </select>
                  <Button
                    size="sm"
                    onClick={() => {
                      setPending({ kind: 'reset', user });
                    }}
                  >
                    Reset
                  </Button>
                  <Button
                    size="sm"
                    variant="dangerOutline"
                    onClick={() => {
                      setPending({ kind: 'remove', user });
                    }}
                  >
                    Remove
                  </Button>
                </>
              ) : (
                <span className="mono" style={{ fontSize: 12 }}>
                  {user.role}
                </span>
              )}
            </div>
          );
        })}
      </div>
      <div style={note}>
        {data?.editable
          ? 'Users added here live in users_file; those in console.yaml change only there. Every change asks for your password and a code, and ends the user’s sessions.'
          : 'users_file is null in console.yaml: users change only in console.yaml.'}
      </div>
      <Dialog
        open={pending !== null}
        label={pending ? title(pending) : 'Users'}
        onClose={() => {
          setPending(null);
        }}
      >
        {pending ? (
          <Confirm
            key={JSON.stringify(pending)}
            pending={pending}
            onClose={() => {
              setPending(null);
            }}
            onDone={(credentials) => {
              toast(`${title(pending)}: done`);
              setPending(null);
              setShown(credentials);
            }}
          />
        ) : null}
      </Dialog>
      <Dialog
        open={shown !== null}
        label={shown ? `Credentials for ${shown.name}` : 'Credentials'}
        onClose={() => {
          setShown(null);
        }}
      >
        {shown ? (
          <Shown
            credentials={shown}
            onClose={() => {
              setShown(null);
            }}
          />
        ) : null}
      </Dialog>
    </Card>
  );
}
