// Settings → Passkeys: the signed-in user's passkeys. Adding one asks for
// the password and a code again; removing one is confirmed first.

import { browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { type SubmitEvent, useState } from 'react';

import type { Passkey } from '../../shared/api.ts';
import { ApiError } from '../lib/api.ts';
import { ago, dateTime } from '../lib/format.ts';
import { passkeyErrorText } from '../lib/passkeys.ts';
import {
  useAddPasskey,
  usePasskeys,
  useRemovePasskey,
} from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { TextInput } from '../ui/controls.tsx';
import { Spinner } from '../ui/Icon.tsx';
import { Dialog } from '../ui/Overlay.tsx';
import { useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

const note = {
  padding: '0 16px 16px',
  fontSize: 12.5,
  color: 'var(--color-text-3)',
  lineHeight: 1.5,
} as const;

function errorText(error: unknown): string {
  return (
    passkeyErrorText(error) ??
    (error instanceof ApiError || error instanceof Error
      ? error.message
      : 'Something went wrong.')
  );
}

function AddPasskey({ onClose }: { onClose: () => void }) {
  const add = useAddPasskey();
  const toast = useToast();
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!name.trim() || !password || !/^\d{6}$/.test(code)) {
      setError('Name the passkey and enter your password and a fresh code.');
      return;
    }
    setError(null);
    add.mutate(
      { name: name.trim(), password, totp: code },
      {
        onSuccess: () => {
          toast(`Passkey "${name.trim()}" added`);
          onClose();
        },
        onError: (failure) => {
          setCode('');
          setError(errorText(failure));
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
      <h2 style={{ fontSize: 18, fontWeight: 600 }}>Add a passkey</h2>
      <p
        style={{
          fontSize: 13.5,
          color: 'var(--color-text-2)',
          lineHeight: 1.5,
        }}
      >
        Confirm it is you, then follow your browser&apos;s prompt. The passkey
        stays on this device, your phone or a security key.
      </p>
      <TextInput
        label="Name"
        placeholder="MacBook, YubiKey…"
        maxLength={64}
        value={name}
        onChange={(event) => {
          setName(event.target.value);
        }}
      />
      <TextInput
        label="Password"
        type="password"
        autoComplete="current-password"
        mono
        value={password}
        onChange={(event) => {
          setPassword(event.target.value);
        }}
      />
      <TextInput
        label="Code"
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
        <Button type="submit" variant="primary" disabled={add.isPending}>
          {add.isPending ? <Spinner /> : null}
          Continue
        </Button>
      </div>
    </form>
  );
}

function PasskeyRow({
  passkey,
  onRemove,
}: {
  passkey: Passkey;
  onRemove: () => void;
}) {
  return (
    <div className={styles.fact} style={{ alignItems: 'center' }}>
      <div style={{ minWidth: 0 }}>
        <div
          style={{
            fontWeight: 500,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {passkey.name}
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          Added {dateTime(passkey.created_at)} ·{' '}
          {passkey.last_used_at === null
            ? 'never used'
            : `used ${ago(passkey.last_used_at)}`}
        </div>
      </div>
      <Button variant="dangerOutline" size="sm" onClick={onRemove}>
        Remove
      </Button>
    </div>
  );
}

export function PasskeysCard() {
  const passkeys = usePasskeys();
  const remove = useRemovePasskey();
  const toast = useToast();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Passkey | null>(null);
  const supported = browserSupportsWebAuthn();
  const data = passkeys.data;

  return (
    <Card
      title="Passkeys"
      aria-label="Passkeys"
      aside={
        data?.enabled && supported ? (
          <Button
            size="sm"
            onClick={() => {
              setAdding(true);
            }}
          >
            Add passkey
          </Button>
        ) : null
      }
    >
      {data && !data.enabled ? (
        <div style={{ ...note, paddingTop: 16 }}>
          Passkeys are off: <span className="mono">passkeys_file</span> is null
          in <span className="mono">console.yaml</span>.
        </div>
      ) : (
        <>
          {data && data.passkeys.length > 0 ? (
            <div className={styles.facts} style={{ margin: 16 }}>
              {data.passkeys.map((passkey) => (
                <PasskeyRow
                  key={passkey.id}
                  passkey={passkey}
                  onRemove={() => {
                    setRemoving(passkey);
                  }}
                />
              ))}
            </div>
          ) : null}
          <div style={{ ...note, paddingTop: data?.passkeys.length ? 0 : 16 }}>
            {data?.passkeys.length
              ? 'Sign in with any of these instead of the password and code, which keep working.'
              : 'No passkeys yet. A passkey signs you in with this device’s screen lock or a security key, instead of the password and code.'}
            {supported ? '' : ' This browser does not support passkeys.'}
          </div>
        </>
      )}
      <Dialog
        open={adding}
        onClose={() => {
          setAdding(false);
        }}
        label="Add a passkey"
      >
        {adding ? (
          <AddPasskey
            onClose={() => {
              setAdding(false);
            }}
          />
        ) : null}
      </Dialog>
      <Dialog
        open={removing !== null}
        onClose={() => {
          setRemoving(null);
        }}
        label="Remove passkey"
      >
        {removing ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600 }}>
              Remove &ldquo;{removing.name}&rdquo;?
            </h2>
            <p
              style={{
                fontSize: 13.5,
                color: 'var(--color-text-2)',
                lineHeight: 1.5,
              }}
            >
              It will no longer sign you in here. Delete it from the device too
              if you do not need it elsewhere.
            </p>
            <div
              style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}
            >
              <Button
                variant="ghost"
                onClick={() => {
                  setRemoving(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                disabled={remove.isPending}
                onClick={() => {
                  const target = removing;
                  remove.mutate(target.id, {
                    onSuccess: () => {
                      toast(`Passkey "${target.name}" removed`);
                      setRemoving(null);
                    },
                    onError: (failure) => {
                      toast(errorText(failure));
                    },
                  });
                }}
              >
                Remove
              </Button>
            </div>
          </div>
        ) : null}
      </Dialog>
    </Card>
  );
}
