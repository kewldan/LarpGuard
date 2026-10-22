import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Analytics } from './analytics/analytics.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { PasskeyStore } from './auth/passkeys.ts';
import { SessionStore } from './auth/sessions.ts';
import { base32Decode, totpAt } from './auth/totp.ts';
import { parseConsoleConfig } from './config.ts';
import type { Deps } from './deps.ts';
import { createMockAdmin, MOCK_SHADOW_HOSTS } from './dev/mock-admin.ts';
import { createMockAnalytics } from './dev/mock-analytics.ts';
import { generateEvents, type MockEvent } from './dev/mock-data.ts';

const ORIGIN = 'https://console.example.com';
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const START = Date.UTC(2026, 9, 19, 12, 0, 0);

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

let events: MockEvent[];
let clock: number;
let deps: Deps;

function code(at = clock): string {
  return totpAt(base32Decode(SECRET), Math.floor(at / 1000));
}

function build(overrides: Partial<Deps> = {}) {
  deps = {
    config,
    admin: createMockAdmin(() => clock),
    analytics: createMockAnalytics(events, () => clock),
    metrics: {
      read: () =>
        Promise.resolve({ healthy: true, metrics: new Map(), rps: 12 }),
    },
    audit: new AuditLog(null, () => clock),
    sessions: new SessionStore({ idleMs: 30 * 60_000, maxMs: 12 * 3_600_000 }),
    passkeys: new PasskeyStore(null),
    now: () => clock,
    staticRoot: null,
    verifyPassword: (password) =>
      Promise.resolve(password === 'right-password'),
    ...overrides,
  };
  return createApp(deps);
}

type App = ReturnType<typeof build>;

async function signIn(app: App, user = 'ops', totp = code()) {
  const response = await app.request('/api/session', {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ username: user, password: 'right-password', totp }),
  });
  const cookie = response.headers.get('set-cookie') ?? '';
  const body = (await response.json()) as { csrf?: string };
  return {
    response,
    cookie: cookie.split(';')[0] ?? '',
    csrf: body.csrf ?? '',
  };
}

function send(
  app: App,
  session: { cookie: string; csrf: string },
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  return app.request(path, {
    method,
    headers: {
      cookie: session.cookie,
      origin: ORIGIN,
      'x-csrf-token': session.csrf,
      'content-type': 'application/json',
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

beforeAll(() => {
  events = generateEvents(START, MOCK_SHADOW_HOSTS);
});

beforeEach(() => {
  clock = START;
});

describe('sign-in', () => {
  it('needs a session for the API', async () => {
    const app = build();
    expect((await app.request('/api/status')).status).toBe(401);
    expect((await app.request('/api/session')).status).toBe(401);
  });

  it('signs in with password and TOTP and sets a host-only secure cookie', async () => {
    const app = build();
    const { response, cookie } = await signIn(app);
    expect(response.status).toBe(200);
    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toMatch(/^__Host-lg_session=/);
    expect(setCookie).toMatch(/HttpOnly/);
    expect(setCookie).toMatch(/Secure/);
    expect(setCookie).toMatch(/SameSite=Strict/);
    const session = await app.request('/api/session', { headers: { cookie } });
    expect(await session.json()).toMatchObject({
      user: { name: 'ops', role: 'operator' },
    });
  });

  it('refuses wrong passwords, wrong codes, replays and other origins', async () => {
    const app = build();
    const wrong = await app.request('/api/session', {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'ops', password: 'nope', totp: code() }),
    });
    expect(wrong.status).toBe(401);
    expect((await signIn(app, 'ops', '000000')).response.status).toBe(401);
    expect((await signIn(app, 'nobody')).response.status).toBe(401);
    expect((await signIn(app)).response.status).toBe(200);
    // The same code twice.
    expect((await signIn(app)).response.status).toBe(401);
    clock += 30_000;
    const elsewhere = await app.request('/api/session', {
      method: 'POST',
      headers: {
        origin: 'https://evil.example',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        username: 'ops',
        password: 'right-password',
        totp: code(),
      }),
    });
    expect(elsewhere.status).toBe(403);
    const failures = deps.audit
      .list(() => false)
      .filter((e) => e.what.startsWith('Failed'));
    expect(failures).toHaveLength(4);
  });

  it('locks a user name after five failures', async () => {
    const app = build();
    for (let i = 0; i < 5; i += 1) {
      expect((await signIn(app, 'ops', '000000')).response.status).toBe(401);
    }
    expect((await signIn(app)).response.status).toBe(429);
    clock += 5 * 60_000 + 30_000;
    expect((await signIn(app)).response.status).toBe(200);
  });

  it('signs out', async () => {
    const app = build();
    const session = await signIn(app);
    const out = await app.request('/api/session', {
      method: 'DELETE',
      headers: { cookie: session.cookie },
    });
    expect(out.status).toBe(204);
    expect(
      (
        await app.request('/api/status', {
          headers: { cookie: session.cookie },
        })
      ).status,
    ).toBe(401);
  });
});

describe('changes', () => {
  it('need the CSRF token and the console origin', async () => {
    const app = build();
    const session = await signIn(app);
    const entry = {
      kind: 'ip',
      value: '203.0.113.0/24',
      action: 'block',
      ttl: '1h',
    };
    expect(
      (await send(app, { ...session, csrf: 'x' }, 'POST', '/api/lists', entry))
        .status,
    ).toBe(403);
    expect(
      (
        await send(app, session, 'POST', '/api/lists', entry, {
          origin: 'https://evil.example',
        })
      ).status,
    ).toBe(403);
    expect((await send(app, session, 'POST', '/api/lists', entry)).status).toBe(
      201,
    );
  });

  it('need the operator role', async () => {
    const app = build();
    const viewer = await signIn(app, 'watcher');
    expect((await send(app, viewer, 'GET', '/api/lists')).status).toBe(200);
    expect(
      (
        await send(app, viewer, 'POST', '/api/attack', {
          host: '*',
          ttl: '15m',
        })
      ).status,
    ).toBe(403);
    expect((await send(app, viewer, 'POST', '/api/reload')).status).toBe(403);
  });

  it('are audited and can be reverted', async () => {
    const app = build();
    const session = await signIn(app);
    const added = await send(app, session, 'POST', '/api/lists', {
      kind: 'ja4',
      value: 't13d1312h2_f57a46bbacb6_*',
      action: 'block',
      comment: 'go clients',
    });
    expect(added.status).toBe(201);
    const audit = (await (
      await send(app, session, 'GET', '/api/audit')
    ).json()) as {
      entries: {
        id: string;
        kind: string;
        revertible: boolean;
        what: string;
      }[];
      intact: boolean;
    };
    const entry = audit.entries.find((e) => e.kind === 'list');
    expect(entry?.what).toBe('Blocked ja4 t13d1312h2_f57a46bbacb6_*');
    expect(entry?.revertible).toBe(true);
    expect(audit.intact).toBe(true);
    expect(
      (await send(app, session, 'POST', `/api/audit/${entry?.id ?? ''}/revert`))
        .status,
    ).toBe(204);
    expect(await deps.admin.lists()).toEqual([]);
    expect(
      (await send(app, session, 'POST', `/api/audit/${entry?.id ?? ''}/revert`))
        .status,
    ).toBe(409);
  });

  it('switch host modes and revert them', async () => {
    const app = build();
    const session = await signIn(app);
    expect(
      (
        await send(app, session, 'POST', '/api/hosts/mode', {
          host: 'shop.example.com',
          mode: 'enforce',
        })
      ).status,
    ).toBe(204);
    expect((await deps.admin.policy('shop.example.com')).mode_source).toBe(
      'console',
    );
    const audit = deps.audit.list(() => true);
    const switched = audit.find((e) => e.kind === 'mode');
    expect(switched?.what).toBe('shop.example.com switched shadow → enforce');
    await send(app, session, 'POST', `/api/audit/${switched?.id ?? ''}/revert`);
    expect((await deps.admin.policy('shop.example.com')).mode_source).toBe(
      'policy.hosts',
    );
  });
});

describe('data', () => {
  it('never passes full addresses through', async () => {
    const leaky: Analytics = {
      ...createMockAnalytics(events, () => clock),
      requests: () =>
        Promise.resolve({
          rows: [
            {
              ...(events[events.length - 1] as MockEvent),
              ip: '203.0.113.77',
            } as unknown as MockEvent,
          ],
          total: 1,
          facets: { action: [], class: [], host: [] },
        }),
    };
    const app = build({ analytics: leaky });
    const session = await signIn(app);
    const response = await send(app, session, 'GET', '/api/requests?range=1h');
    expect(response.status).toBe(200);
    expect(await response.text()).not.toContain('203.0.113.77');
  });

  it('validates filters', async () => {
    const app = build();
    const session = await signIn(app);
    expect(
      (await send(app, session, 'GET', '/api/requests?range=2y')).status,
    ).toBe(400);
    expect(
      (await send(app, session, 'GET', '/api/requests?action=explode')).status,
    ).toBe(400);
    const page = (await (
      await send(
        app,
        session,
        'GET',
        '/api/requests?range=1h&action=block&limit=5',
      )
    ).json()) as { rows: { action: string }[]; total: number };
    expect(page.rows.length).toBeLessThanOrEqual(5);
    expect(page.rows.every((row) => row.action === 'block')).toBe(true);
  });

  it('says when ClickHouse is not configured', async () => {
    const app = build({ analytics: null });
    const session = await signIn(app);
    const response = await send(app, session, 'GET', '/api/overview?range=1h');
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      error: 'ClickHouse is not configured',
    });
    const status = (await (
      await send(app, session, 'GET', '/api/status')
    ).json()) as {
      health: { clickhouse: string };
    };
    expect(status.health.clickhouse).toBe('off');
  });

  it('tests rules and reports compile errors with the column', async () => {
    const app = build();
    const session = await signIn(app);
    const bad = await send(app, session, 'POST', '/api/rules/test', {
      when: 'score > 40 and hosst == "a"',
      action: 'block',
    });
    expect(bad.status).toBe(422);
    expect(await bad.json()).toEqual({
      error: "col 16: unknown name 'hosst'",
      column: 16,
    });
    const good = (await (
      await send(app, session, 'POST', '/api/rules/test', {
        when: 'score >= 70 and header("x-a") == ""',
        action: 'block',
      })
    ).json()) as { matched: number; sampled: number; approximate: string[] };
    expect(good.sampled).toBeGreaterThan(0);
    expect(good.matched).toBeGreaterThan(0);
    expect(good.approximate).toEqual(['header()']);
  });
});

describe('the SPA', () => {
  let root: string;
  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('serves index.html for client routes, with security headers', async () => {
    root = mkdtempSync(join(tmpdir(), 'lg-web-'));
    writeFileSync(
      join(root, 'index.html'),
      '<!doctype html><title>LarpGuard</title>',
    );
    const app = build({ staticRoot: root });
    const page = await app.request('/requests?range=1h');
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('<title>LarpGuard</title>');
    expect(page.headers.get('content-security-policy')).toContain(
      "frame-ancestors 'none'",
    );
    expect(page.headers.get('strict-transport-security')).toBe(
      'max-age=31536000',
    );
    expect((await app.request('/api/nope')).status).toBe(401);
  });
});
