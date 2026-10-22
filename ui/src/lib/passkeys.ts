// Passkey ceremonies in the browser: the server's options go to the
// authenticator (via @simplewebauthn/browser), its answer back to the
// server, which checks it.

import {
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  startAuthentication,
  startRegistration,
  WebAuthnError,
} from '@simplewebauthn/browser';

import {
  passkeyOptionsSchema,
  type Session,
  sessionSchema,
} from '../../shared/api.ts';
import { send, sendJson } from './api.ts';

// The authenticator's refusals in words; null for other errors.
export function passkeyErrorText(error: unknown): string | null {
  const name =
    error instanceof WebAuthnError
      ? (error.cause as { name?: string } | undefined)?.name
      : error instanceof DOMException
        ? error.name
        : undefined;
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return 'Cancelled, or the passkey prompt timed out.';
  }
  if (name === 'InvalidStateError') {
    return 'This authenticator already holds a passkey for you here.';
  }
  if (name === 'SecurityError') {
    return 'This browser refused passkeys for this address (HTTPS is required).';
  }
  return null;
}

export async function signInWithPasskey(): Promise<Session> {
  const { ceremony, options } = await sendJson(
    passkeyOptionsSchema,
    'POST',
    '/api/session/passkey/options',
  );
  const response = await startAuthentication({
    optionsJSON: options as PublicKeyCredentialRequestOptionsJSON,
  });
  return sendJson(sessionSchema, 'POST', '/api/session/passkey', {
    ceremony,
    response,
  });
}

export async function addPasskey(change: {
  name: string;
  password: string;
  totp: string;
}): Promise<void> {
  const { options } = await sendJson(
    passkeyOptionsSchema,
    'POST',
    '/api/passkeys/options',
    { password: change.password, totp: change.totp },
  );
  const response = await startRegistration({
    optionsJSON: options as PublicKeyCredentialCreationOptionsJSON,
  });
  await send('POST', '/api/passkeys', { name: change.name, response });
}
