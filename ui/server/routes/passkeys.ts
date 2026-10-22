// Passkeys: sign-in with a passkey (no session yet), and a user's own
// passkeys (list, add after re-entering password and code, remove). Any
// role manages its own passkeys: they change sign-in, not the gateway.
//
// POST   /api/session/passkey/options   challenge for a passkey sign-in
// POST   /api/session/passkey           sign in with a passkey
// GET    /api/passkeys                  own passkeys
// POST   /api/passkeys/options          password + code -> registration options
// POST   /api/passkeys                  register the new passkey
// DELETE /api/passkeys/:id              remove an own passkey

import { createHash, randomBytes } from 'node:crypto';

import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { Context, Hono } from 'hono';

import {
  newPasskeySchema,
  passkeyListSchema,
  passkeyOptionsSchema,
  passkeyReauthSchema,
  passkeySignInSchema,
  type Session,
  sessionSchema,
} from '../../shared/api.ts';
import {
  ChallengeStore,
  MAX_PASSKEYS_PER_USER,
  type PasskeyStore,
} from '../auth/passkeys.ts';
import type { SessionData } from '../auth/sessions.ts';
import type { SignInGuard } from '../auth/signin.ts';
import type { ConsoleUser } from '../config.ts';
import type { AppEnv } from '../deps.ts';
import { fail, jsonBody, parseOr400, send } from '../http.ts';

export interface PasskeyContext {
  guard: SignInGuard;
  users: Map<string, ConsoleUser>;
  origin: string;
  // The client's network (a /24 or /48), for the limiter and the audit.
  network: (c: Context<AppEnv>) => string;
  // Starts a session (cookie and audit); answers with the session JSON.
  openSession: (
    c: Context<AppEnv>,
    user: ConsoleUser,
    how: string,
  ) => SessionData;
  sessionJson: (session: SessionData) => Session;
}

const RP_NAME = 'LarpGuard console';

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

function store(c: Context<AppEnv>): PasskeyStore {
  const passkeys = c.get('deps').passkeys;
  if (!passkeys) fail(404, 'passkeys are turned off (passkeys_file: null)');
  return passkeys;
}

// A stable WebAuthn user handle per user name: registering again on the
// same authenticator replaces the old passkey instead of adding a twin.
function userHandle(name: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(
    createHash('sha256').update(`larpguard-console:${name}`).digest(),
  );
}

function lockedMessage(ms: number): string {
  return `too many failed sign-ins, try again in ${Math.ceil(ms / 60_000)} min`;
}

// Before the session middleware: no session needed.
export function registerPasskeySignIn(
  app: Hono<AppEnv>,
  ctx: PasskeyContext,
): void {
  const rpID = new URL(ctx.origin).hostname;
  const challenges = new ChallengeStore();

  app.post('/api/session/passkey/options', async (c) => {
    if (c.req.header('origin') !== ctx.origin)
      fail(403, 'cross-origin request');
    store(c);
    const deps = c.get('deps');
    const now = deps.now();
    const locked = ctx.guard.lockedFor([`net:${ctx.network(c)}`], now);
    if (locked > 0) fail(429, lockedMessage(locked));
    // Discoverable credentials: the authenticator offers this site's
    // passkeys, so the browser never learns which users exist.
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
      timeout: 120_000,
    });
    const ceremony = randomBytes(24).toString('base64url');
    challenges.put(ceremony, options.challenge, now);
    return send(c, passkeyOptionsSchema, { ceremony, options });
  });

  app.post('/api/session/passkey', async (c) => {
    if (c.req.header('origin') !== ctx.origin)
      fail(403, 'cross-origin request');
    const passkeys = store(c);
    const deps = c.get('deps');
    const body = parseOr400(passkeySignInSchema, await jsonBody(c));
    const now = deps.now();
    const network = ctx.network(c);
    const passkey = passkeys.find(body.response.id);
    const user = passkey ? ctx.users.get(passkey.user) : undefined;
    const keys = [`net:${network}`, ...(user ? [`user:${user.name}`] : [])];
    const locked = ctx.guard.lockedFor(keys, now);
    if (locked > 0) fail(429, lockedMessage(locked));
    const challenge = challenges.take(body.ceremony, now);
    let reason = 'unknown passkey';
    let newCounter: number | null = null;
    if (!challenge) {
      reason = 'expired or reused challenge';
    } else if (passkey && user) {
      try {
        const result = await verifyAuthenticationResponse({
          response: body.response as unknown as AuthenticationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: ctx.origin,
          expectedRPID: rpID,
          requireUserVerification: true,
          credential: {
            id: passkey.id,
            publicKey: Buffer.from(passkey.public_key, 'base64url'),
            counter: passkey.counter,
            transports: passkey.transports,
          },
        });
        if (result.verified) newCounter = result.authenticationInfo.newCounter;
        else reason = 'signature did not verify';
      } catch (error) {
        reason = error instanceof Error ? error.message : 'invalid response';
      }
    }
    if (!passkey || !user || newCounter === null) {
      const lockedNow = ctx.guard.fail(keys, now);
      deps.audit.append({
        kind: 'auth',
        actor: user ? user.name : 'unknown',
        what: `Failed passkey sign-in${lockedNow ? ', locked 5 min' : ''}`,
        facts: [
          ['From', network],
          ['Reason', reason.slice(0, 200)],
        ],
      });
      return fail(401, 'this passkey was not accepted');
    }
    ctx.guard.succeed(keys);
    passkeys.used(passkey.id, newCounter, now);
    const session = ctx.openSession(c, user, `passkey "${passkey.name}"`);
    return send(c, sessionSchema, ctx.sessionJson(session));
  });
}

// After the session middleware: the signed-in user's own passkeys.
export function registerPasskeys(app: Hono<AppEnv>, ctx: PasskeyContext): void {
  const rpID = new URL(ctx.origin).hostname;
  const challenges = new ChallengeStore();

  app.get('/api/passkeys', (c) => {
    const passkeys = c.get('deps').passkeys;
    const session = c.get('session');
    return send(c, passkeyListSchema, {
      enabled: passkeys !== null,
      passkeys: (passkeys?.forUser(session.user) ?? []).map((passkey) => ({
        id: passkey.id,
        name: passkey.name,
        created_at: passkey.created_at,
        last_used_at: passkey.last_used_at,
      })),
    });
  });

  app.post('/api/passkeys/options', async (c) => {
    const passkeys = store(c);
    const deps = c.get('deps');
    const session = c.get('session');
    const body = parseOr400(passkeyReauthSchema, await jsonBody(c));
    const now = deps.now();
    const network = ctx.network(c);
    const keys = [`user:${session.user}`, `net:${network}`];
    const locked = ctx.guard.lockedFor(keys, now);
    if (locked > 0) fail(429, lockedMessage(locked));
    const user = ctx.users.get(session.user);
    const result = await ctx.guard.check(user, body.password, body.totp, now);
    if (!user || result !== 'ok') {
      const lockedNow = ctx.guard.fail(keys, now);
      deps.audit.append({
        kind: 'auth',
        actor: session.user,
        what: `Failed check before adding a passkey${lockedNow ? ', locked 5 min' : ''}`,
        facts: [
          ['From', network],
          [
            'Reason',
            result === 'replay' ? 'code already used' : 'wrong credentials',
          ],
        ],
      });
      // 403, not 401: the session itself is fine.
      return fail(403, 'wrong password or code');
    }
    ctx.guard.succeed(keys);
    const own = passkeys.forUser(user.name);
    if (own.length >= MAX_PASSKEYS_PER_USER) {
      fail(409, `at most ${MAX_PASSKEYS_PER_USER} passkeys per user`);
    }
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID,
      userName: user.name,
      userID: userHandle(user.name),
      attestationType: 'none',
      excludeCredentials: own.map((passkey) => ({
        id: passkey.id,
        transports: passkey.transports,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      timeout: 120_000,
    });
    challenges.put(session.id, options.challenge, now);
    return send(c, passkeyOptionsSchema, { options });
  });

  app.post('/api/passkeys', async (c) => {
    const passkeys = store(c);
    const deps = c.get('deps');
    const session = c.get('session');
    const body = parseOr400(newPasskeySchema, await jsonBody(c));
    const now = deps.now();
    const challenge = challenges.take(session.id, now);
    if (!challenge) {
      fail(409, 'the registration expired, start again');
    }
    let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    try {
      verified = await verifyRegistrationResponse({
        response: body.response as unknown as RegistrationResponseJSON,
        expectedChallenge: challenge,
        expectedOrigin: ctx.origin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });
    } catch (error) {
      return fail(
        422,
        `passkey not accepted: ${error instanceof Error ? error.message : 'invalid response'}`,
      );
    }
    if (!verified.verified) return fail(422, 'passkey not accepted');
    const { credential } = verified.registrationInfo;
    if (passkeys.find(credential.id)) {
      fail(409, 'this passkey is already registered');
    }
    passkeys.add({
      id: credential.id,
      user: session.user,
      name: body.name,
      public_key: b64url(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports ?? [],
      created_at: now,
      last_used_at: null,
    });
    deps.audit.append({
      kind: 'auth',
      actor: session.user,
      what: `Added passkey "${body.name}"`,
      facts: [['From', ctx.network(c)]],
    });
    return c.body(null, 204);
  });

  app.delete('/api/passkeys/:id', (c) => {
    const passkeys = store(c);
    const deps = c.get('deps');
    const session = c.get('session');
    const removed = passkeys.remove(session.user, c.req.param('id'));
    if (!removed) return fail(404, 'no such passkey');
    deps.audit.append({
      kind: 'auth',
      actor: session.user,
      what: `Removed passkey "${removed.name}"`,
      facts: [['From', ctx.network(c)]],
    });
    return c.body(null, 204);
  });
}
