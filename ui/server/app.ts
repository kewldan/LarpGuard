// The console's HTTP app: security headers, the session API, the API
// routes behind a session (and a role and CSRF check for changes), and the
// SPA.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { monitorEventLoopDelay } from 'node:perf_hooks';

import { serveStatic } from '@hono/node-server/serve-static';
import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';

import {
  loginSchema,
  pingSchema,
  sessionSchema,
  whoamiSchema,
} from '../shared/api.ts';
import { type SessionData, safeEqual } from './auth/sessions.ts';
import { SignInGuard } from './auth/signin.ts';
import { UserDirectory } from './auth/users.ts';
import { type ConsoleUser, secureCookies } from './config.ts';
import type { AppEnv, Deps } from './deps.ts';
import {
  addressPrefix,
  errorResponse,
  fail,
  jsonBody,
  parseOr400,
  send,
} from './http.ts';
import { registerRoutes } from './routes/index.ts';
import {
  type PasskeyContext,
  registerPasskeySignIn,
  registerPasskeys,
} from './routes/passkeys.ts';
import { registerUsers } from './routes/users.ts';

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function cookieName(deps: Deps): string {
  return secureCookies(deps.config) ? '__Host-lg_session' : 'lg_session';
}

// The client's address: the socket peer or, behind proxies on loopback
// (gateway and Traefik on the same host), the nearest non-loopback hop of
// X-Forwarded-For.
function clientAddress(c: Context<AppEnv>): string {
  // No bindings at all under app.request() (tests).
  const env = c.env as AppEnv['Bindings'] | undefined;
  const peer = env?.incoming?.socket.remoteAddress ?? '';
  const loopback = (address: string) =>
    /^(127\.|::1$|::ffff:127\.)/.test(address);
  const forwarded = c.req.header('x-forwarded-for');
  if (!loopback(peer) || !forwarded) return peer;
  const hops = forwarded.split(',').map((hop) => hop.trim());
  for (let i = hops.length - 1; i >= 0; i -= 1) {
    const hop = hops[i] ?? '';
    if (hop && !loopback(hop)) return hop;
  }
  return peer;
}

// The connection check's server side. The gateway is asked at most every
// few seconds whoever probes, so anonymous probes cannot flood its admin
// socket; a call that hangs counts as no answer.
const kGatewayCheckEvery = 5_000;
const kGatewayTimeout = 2_000;
// Event-loop lag is a recent figure: the histogram restarts this often.
const kLoopWindow = 10_000;
const kLoopResolution = 20;

function createServerProbe(deps: Deps): () => Promise<{
  loop_ms: number;
  gateway_ms: number | null;
}> {
  const loop = monitorEventLoopDelay({ resolution: kLoopResolution });
  loop.enable();
  let loopSince = performance.now();
  let gateway: { at: number; ms: Promise<number | null> } | null = null;
  return async () => {
    const now = performance.now();
    if (gateway === null || now - gateway.at >= kGatewayCheckEvery) {
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<null>((resolve) => {
        timer = setTimeout(() => {
          resolve(null);
        }, kGatewayTimeout);
      });
      const answer = deps.admin.status().then(
        () => performance.now() - now,
        () => null,
      );
      gateway = {
        at: now,
        ms: Promise.race([answer, timeout]).finally(() => {
          clearTimeout(timer);
        }),
      };
    }
    // Delays are measured against the sampling interval; only the excess
    // is lag. No samples yet reads as NaN.
    const p99 = loop.percentile(99) / 1e6 - kLoopResolution;
    if (now - loopSince >= kLoopWindow) {
      loop.reset();
      loopSince = now;
    }
    return {
      loop_ms: Number.isFinite(p99) ? Math.max(0, p99) : 0,
      gateway_ms: await gateway.ms,
    };
  };
}

export function createApp(deps: Deps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const cookie = cookieName(deps);
  const secure = secureCookies(deps.config);
  const origin = new URL(deps.config.public_origin).origin;
  const users = new UserDirectory(deps.config.users, deps.config.users_file);
  const guard = new SignInGuard(deps.verifyPassword);
  const network = (c: Context<AppEnv>) =>
    addressPrefix(clientAddress(c)) || 'unknown';

  app.onError((error) => {
    const response = errorResponse(error);
    if (response.status === 500) console.error(error);
    return response;
  });

  app.use('*', async (c, next) => {
    c.set('deps', deps);
    await next();
    c.header('Content-Security-Policy', CSP);
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('Cross-Origin-Opener-Policy', 'same-origin');
    c.header('Cross-Origin-Resource-Policy', 'same-origin');
    c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (secure) {
      c.header('Strict-Transport-Security', 'max-age=31536000');
    }
    if (c.req.path.startsWith('/api/')) c.header('Cache-Control', 'no-store');
  });

  const sessionJson = (session: SessionData) => ({
    user: { name: session.user, role: session.role },
    csrf: session.csrf,
    expires_at: deps.sessions.expiresAt(session),
  });

  const openSession = (
    c: Context<AppEnv>,
    user: ConsoleUser,
    how: string,
  ): SessionData => {
    const session = deps.sessions.create(user.name, user.role, deps.now());
    setCookie(c, cookie, session.id, {
      httpOnly: true,
      secure,
      sameSite: 'Strict',
      path: '/',
      maxAge: Math.floor(deps.config.session.max / 1000),
    });
    deps.audit.append({
      kind: 'auth',
      actor: user.name,
      what: 'Signed in',
      facts: [
        ['From', network(c)],
        ['Role', user.role],
        ['With', how],
      ],
    });
    return session;
  };

  const passkeys: PasskeyContext = {
    guard,
    users,
    origin,
    network,
    openSession,
    sessionJson,
  };

  // --- Session API (no session needed) ----------------------------------

  app.get('/api/session', (c) => {
    const session = deps.sessions.get(getCookie(c, cookie), deps.now());
    if (!session) return fail(401, 'not signed in');
    return send(c, sessionSchema, sessionJson(session));
  });

  app.post('/api/session', async (c) => {
    if (c.req.header('origin') !== origin) fail(403, 'cross-origin request');
    const login = parseOr400(loginSchema, await jsonBody(c));
    const now = deps.now();
    const from = network(c);
    const keys = [`user:${login.username}`, `net:${from}`];
    const locked = guard.lockedFor(keys, now);
    if (locked > 0) {
      fail(
        429,
        `too many failed sign-ins, try again in ${Math.ceil(locked / 60_000)} min`,
      );
    }
    const user = users.get(login.username);
    const result = await guard.check(user, login.password, login.totp, now);
    if (!user || result !== 'ok') {
      const lockedNow = guard.fail(keys, now);
      deps.audit.append({
        kind: 'auth',
        actor: user ? user.name : 'unknown',
        what: `Failed sign-in for "${login.username}"${lockedNow ? ', locked 5 min' : ''}`,
        facts: [
          ['From', from],
          [
            'Reason',
            result === 'replay' ? 'code already used' : 'wrong credentials',
          ],
        ],
      });
      return fail(401, 'wrong user name, password or code');
    }
    guard.succeed(keys);
    const session = openSession(c, user, 'password and code');
    return send(c, sessionSchema, sessionJson(session));
  });

  registerPasskeySignIn(app, passkeys);

  // The gateway's verdict on this very request (sign-in screen). Its
  // headers are trustworthy only behind the gateway, which strips client
  // X-Bot-*; anywhere else they are just shown back.
  app.get('/api/whoami', (c) => {
    const score = Number(c.req.header('x-bot-score'));
    const reasons = c.req.header('x-bot-reasons');
    const prefix = addressPrefix(clientAddress(c));
    return send(c, whoamiSchema, {
      score:
        Number.isInteger(score) && c.req.header('x-bot-score') ? score : null,
      class: c.req.header('x-bot-class') ?? null,
      reasons: reasons && reasons !== '-' ? reasons.split(',') : [],
      request_id: c.req.header('x-bot-request-id') ?? null,
      ip_prefix: prefix || null,
      passkeys: deps.passkeys !== null,
    });
  });

  // The connection check on the sign-in screen (shared/api.ts pingSchema).
  const probeServer = createServerProbe(deps);
  app.get('/api/ping', async (c) => {
    const started = performance.now();
    const server = await probeServer();
    return send(c, pingSchema, {
      server_ms: performance.now() - started,
      ...server,
    });
  });

  app.delete('/api/session', (c) => {
    const id = getCookie(c, cookie);
    if (id) deps.sessions.destroy(id);
    deleteCookie(c, cookie, { path: '/', secure });
    return c.body(null, 204);
  });

  // --- Everything else under /api needs a session -----------------------

  app.use('/api/*', async (c, next) => {
    // Middleware contexts carry an `any` input; the cookie helper does not
    // care.
    const session = deps.sessions.get(
      getCookie(c as Context<AppEnv>, cookie),
      deps.now(),
    );
    if (!session) return fail(401, 'not signed in');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
      if (c.req.header('origin') !== origin) fail(403, 'cross-origin request');
      const token = c.req.header('x-csrf-token') ?? '';
      if (!safeEqual(token, session.csrf))
        fail(403, 'missing or wrong CSRF token');
    }
    c.set('session', session);
    await next();
  });

  registerRoutes(app);
  registerPasskeys(app, passkeys);
  registerUsers(app, { guard, users, network });

  app.all('/api/*', () => fail(404, 'unknown endpoint'));

  // --- The SPA ------------------------------------------------------------

  if (deps.staticRoot !== null) {
    const root = deps.staticRoot;
    const indexPath = join(root, 'index.html');
    const index = existsSync(indexPath)
      ? readFileSync(indexPath, 'utf8')
      : null;
    app.use(
      '/assets/*',
      serveStatic({
        root,
        onFound: (_path, c) => {
          // Hashed file names: cache for a year.
          c.header('Cache-Control', 'public, max-age=31536000, immutable');
        },
      }),
    );
    app.use('*', serveStatic({ root }));
    // Client-side routes all get index.html.
    app.get('*', (c) => {
      if (index === null) return fail(404, 'console not built');
      c.header('Cache-Control', 'no-cache');
      return c.html(index);
    });
  }

  return app;
}
