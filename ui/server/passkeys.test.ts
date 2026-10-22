import {
  createHash,
  createSign,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
} from 'node:crypto';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isoCBOR } from '@simplewebauthn/server/helpers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { ChallengeStore, PasskeyStore } from './auth/passkeys.ts';
import { SessionStore } from './auth/sessions.ts';
import { base32Decode, totpAt } from './auth/totp.ts';
import { parseConsoleConfig } from './config.ts';
import type { Deps } from './deps.ts';
import { createMockAdmin } from './dev/mock-admin.ts';

const ORIGIN = 'https://console.example.com';
const RP_ID = 'console.example.com';
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const START = Date.UTC(2026, 9, 22, 12, 0, 0);

const config = parseConsoleConfig(`
public_origin: ${ORIGIN}
audit_log: /dev/null
users:
  - name: ops
    role: operator
    password: scrypt$10$8$1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    totp_secret: ${SECRET}
  - name: watcher
    role: viewer
    password: scrypt$10$8$1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    totp_secret: ${SECRET}
`);

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const sha256 = (data: Uint8Array | string) =>
  createHash('sha256').update(data).digest();

// A software authenticator: one P-256 key, "none" attestation, user
// presence and verification always set.
class Authenticator {
  readonly id = randomBytes(16);
  private readonly key: KeyObject;
  private readonly cose: Uint8Array;
  private counter = 0;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    this.key = privateKey;
    const jwk = publicKey.export({ format: 'jwk' });
    this.cose = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x ?? '', 'base64url')],
        [-3, Buffer.from(jwk.y ?? '', 'base64url')],
      ]),
    );
  }

  register(challenge: string, origin = ORIGIN) {
    const clientData = Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge, origin }),
    );
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(this.id.length);
    const authData = Buffer.concat([
      sha256(RP_ID),
      Buffer.from([0x45]), // UP | UV | AT
      Buffer.alloc(4),
      Buffer.alloc(16), // AAGUID
      idLength,
      this.id,
      this.cose,
    ]);
    const attestation = isoCBOR.encode(
      new Map<string, string | Map<string, string> | Uint8Array>([
        ['fmt', 'none'],
        ['attStmt', new Map<string, string>()],
        ['authData', authData],
      ]),
    );
    return {
      id: b64url(this.id),
      rawId: b64url(this.id),
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientData),
        attestationObject: b64url(attestation),
        transports: ['internal'],
      },
      clientExtensionResults: {},
    };
  }

  assert(challenge: string, origin = ORIGIN) {
    this.counter += 1;
    const clientData = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge, origin }),
    );
    const count = Buffer.alloc(4);
    count.writeUInt32BE(this.counter);
    const authData = Buffer.concat([
      sha256(RP_ID),
      Buffer.from([0x05]), // UP | UV
      count,
    ]);
    const signer = createSign('sha256');
    signer.update(Buffer.concat([authData, sha256(clientData)]));
    return {
      id: b64url(this.id),
      rawId: b64url(this.id),
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientData),
        authenticatorData: b64url(authData),
        signature: b64url(signer.sign(this.key)),
      },
      clientExtensionResults: {},
    };
  }
}

let clock: number;
let audit: AuditLog;

function build(overrides: Partial<Deps> = {}) {
  audit = new AuditLog(null, () => clock);
  return createApp({
    config,
    admin: createMockAdmin(() => clock),
    analytics: null,
    metrics: {
      read: () =>
        Promise.resolve({ healthy: true, metrics: new Map(), rps: 0 }),
    },
    audit,
    sessions: new SessionStore({ idleMs: 30 * 60_000, maxMs: 12 * 3_600_000 }),
    passkeys: new PasskeyStore(null),
    now: () => clock,
    staticRoot: null,
    verifyPassword: (password) =>
      Promise.resolve(password === 'right-password'),
    ...overrides,
  });
}

type App = ReturnType<typeof build>;

const code = () => totpAt(base32Decode(SECRET), Math.floor(clock / 1000));

async function signIn(app: App, user = 'ops') {
  const response = await app.request('/api/session', {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({
      username: user,
      password: 'right-password',
      totp: code(),
    }),
  });
  expect(response.status).toBe(200);
  // The next TOTP step, so later checks get a fresh code.
  clock += 30_000;
  const body = (await response.json()) as { csrf: string };
  return {
    cookie: (response.headers.get('set-cookie') ?? '').split(';')[0] ?? '',
    csrf: body.csrf,
  };
}

function call(
  app: App,
  session: { cookie: string; csrf: string } | null,
  method: string,
  path: string,
  body?: unknown,
) {
  return app.request(path, {
    method,
    headers: {
      origin: ORIGIN,
      'content-type': 'application/json',
      ...(session
        ? { cookie: session.cookie, 'x-csrf-token': session.csrf }
        : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function register(
  app: App,
  session: { cookie: string; csrf: string },
  device: Authenticator,
  name = 'Laptop',
) {
  const options = await call(app, session, 'POST', '/api/passkeys/options', {
    password: 'right-password',
    totp: code(),
  });
  expect(options.status).toBe(200);
  clock += 30_000;
  const { options: json } = (await options.json()) as {
    options: { challenge: string; rp: { id: string } };
  };
  expect(json.rp.id).toBe(RP_ID);
  return call(app, session, 'POST', '/api/passkeys', {
    name,
    response: device.register(json.challenge),
  });
}

async function passkeySignIn(app: App, device: Authenticator, origin = ORIGIN) {
  const options = await call(app, null, 'POST', '/api/session/passkey/options');
  expect(options.status).toBe(200);
  const { ceremony, options: json } = (await options.json()) as {
    ceremony: string;
    options: { challenge: string };
  };
  const response = device.assert(json.challenge, origin);
  return {
    ceremony,
    response,
    result: await call(app, null, 'POST', '/api/session/passkey', {
      ceremony,
      response,
    }),
  };
}

beforeEach(() => {
  clock = START;
});

describe('passkeys', () => {
  it('registers a passkey and signs in with it', async () => {
    const app = build();
    const session = await signIn(app);
    const device = new Authenticator();
    expect((await register(app, session, device)).status).toBe(204);

    const list = (await (
      await call(app, session, 'GET', '/api/passkeys')
    ).json()) as { enabled: boolean; passkeys: { name: string }[] };
    expect(list).toMatchObject({
      enabled: true,
      passkeys: [{ name: 'Laptop' }],
    });

    const { result } = await passkeySignIn(app, device);
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({
      user: { name: 'ops', role: 'operator' },
    });
    expect(result.headers.get('set-cookie')).toContain('__Host-lg_session=');
    const after = (await (
      await call(app, session, 'GET', '/api/passkeys')
    ).json()) as { passkeys: { last_used_at: number | null }[] };
    expect(after.passkeys[0]?.last_used_at).toBe(clock);
    const whats = audit.list(() => false).map((entry) => entry.what);
    expect(whats).toContain('Added passkey "Laptop"');
    expect(
      audit
        .list(() => false)
        .some((entry) =>
          entry.facts.some(
            ([k, v]) => k === 'With' && v === 'passkey "Laptop"',
          ),
        ),
    ).toBe(true);
  });

  it('refuses unknown passkeys, reused challenges and other origins', async () => {
    const app = build();
    const session = await signIn(app);
    const device = new Authenticator();
    await register(app, session, device);

    expect((await passkeySignIn(app, new Authenticator())).result.status).toBe(
      401,
    );
    const first = await passkeySignIn(app, device);
    expect(first.result.status).toBe(200);
    const replay = await call(app, null, 'POST', '/api/session/passkey', {
      ceremony: first.ceremony,
      response: first.response,
    });
    expect(replay.status).toBe(401);
    expect(
      (await passkeySignIn(app, device, 'https://evil.example')).result.status,
    ).toBe(401);
    expect(
      audit
        .list(() => false)
        .filter((entry) => entry.what === 'Failed passkey sign-in'),
    ).toHaveLength(3);
  });

  it('asks for the password and a fresh code before adding one', async () => {
    const app = build();
    const session = await signIn(app);
    const wrong = await call(app, session, 'POST', '/api/passkeys/options', {
      password: 'wrong',
      totp: code(),
    });
    // 403, not 401: the session stays.
    expect(wrong.status).toBe(403);
    expect((await call(app, session, 'GET', '/api/session')).status).toBe(200);
    // The code of the sign-in itself is spent.
    const replay = await call(app, session, 'POST', '/api/passkeys/options', {
      password: 'right-password',
      totp: totpAt(base32Decode(SECRET), Math.floor((clock - 30_000) / 1000)),
    });
    expect(replay.status).toBe(403);
    // Registering without options: no challenge.
    const stray = await call(app, session, 'POST', '/api/passkeys', {
      name: 'x',
      response: new Authenticator().register('nope'),
    });
    expect(stray.status).toBe(409);
    // Needs CSRF like every change.
    const noCsrf = await call(
      app,
      { cookie: session.cookie, csrf: 'bad' },
      'POST',
      '/api/passkeys/options',
      { password: 'right-password', totp: code() },
    );
    expect(noCsrf.status).toBe(403);
  });

  it('lets each user list and remove only their own', async () => {
    const app = build();
    const ops = await signIn(app);
    await register(app, ops, new Authenticator(), 'Ops key');
    const watcher = await signIn(app, 'watcher');
    const theirs = (await (
      await call(app, watcher, 'GET', '/api/passkeys')
    ).json()) as { passkeys: unknown[] };
    expect(theirs.passkeys).toHaveLength(0);
    const own = (await (
      await call(app, ops, 'GET', '/api/passkeys')
    ).json()) as {
      passkeys: { id: string }[];
    };
    const id = own.passkeys[0]?.id ?? '';
    expect(
      (await call(app, watcher, 'DELETE', `/api/passkeys/${id}`)).status,
    ).toBe(404);
    expect((await call(app, ops, 'DELETE', `/api/passkeys/${id}`)).status).toBe(
      204,
    );
    expect(audit.list(() => false).map((entry) => entry.what)).toContain(
      'Removed passkey "Ops key"',
    );
  });

  it('is off without a store', async () => {
    const app = build({ passkeys: null });
    const whoami = (await (await app.request('/api/whoami')).json()) as {
      passkeys: boolean;
    };
    expect(whoami.passkeys).toBe(false);
    expect(
      (await call(app, null, 'POST', '/api/session/passkey/options')).status,
    ).toBe(404);
    const session = await signIn(app);
    expect(
      await (await call(app, session, 'GET', '/api/passkeys')).json(),
    ).toEqual({ enabled: false, passkeys: [] });
  });
});

describe('PasskeyStore', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'lg-passkeys-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('keeps passkeys in a private file', () => {
    const path = join(dir, 'passkeys.json');
    const store = new PasskeyStore(path);
    store.add({
      id: 'abc',
      user: 'ops',
      name: 'Key',
      public_key: 'AQID',
      counter: 0,
      transports: [],
      created_at: 1,
      last_used_at: null,
    });
    store.used('abc', 5, 2);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const reloaded = new PasskeyStore(path);
    expect(reloaded.find('abc')).toMatchObject({ counter: 5, last_used_at: 2 });
    expect(reloaded.remove('someone-else', 'abc')).toBeNull();
    expect(reloaded.remove('ops', 'abc')?.name).toBe('Key');
    expect(new PasskeyStore(path).forUser('ops')).toHaveLength(0);
  });
});

describe('ChallengeStore', () => {
  it('hands out a challenge once and only while fresh', () => {
    const challenges = new ChallengeStore();
    challenges.put('a', 'x', 0);
    expect(challenges.take('a', 1)).toBe('x');
    expect(challenges.take('a', 1)).toBeNull();
    challenges.put('b', 'y', 0);
    expect(challenges.take('b', 5 * 60_000)).toBeNull();
  });
});
