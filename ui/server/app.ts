// The console's HTTP app: security headers, the session API, the API
// routes behind a session (and a role and CSRF check for changes), and the
// SPA.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { serveStatic } from '@hono/node-server/serve-static';
import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';

import { loginSchema, sessionSchema, whoamiSchema } from '../shared/api.ts';
import { FailureLimiter } from './auth/limiter.ts';
import { safeEqual, type SessionData } from './auth/sessions.ts';
import { verifyTotp } from './auth/totp.ts';
import { secureCookies } from './config.ts';
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

// A password check that costs the same for unknown users.
const DUMMY_HASH =
  'scrypt$17$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

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

export function createApp(deps: Deps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const cookie = cookieName(deps);
  const secure = secureCookies(deps.config);
  const origin = new URL(deps.config.public_origin).origin;
  const users = new Map(deps.config.users.map((user) => [user.name, user]));
  // Five failures in five minutes lock a name or a client network for five
  // minutes.
  const limiter = new FailureLimiter({
    limit: 5,
    windowMs: 5 * 60_000,
    lockMs: 5 * 60_000,
  });
  // A TOTP code works once.
  const usedSteps = new Map<string, number>();

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
    const network = addressPrefix(clientAddress(c)) || 'unknown';
    const keys = [`user:${login.username}`, `net:${network}`];
    const locked = Math.max(...keys.map((key) => limiter.lockedFor(key, now)));
    if (locked > 0) {
      fail(
        429,
        `too many failed sign-ins, try again in ${Math.ceil(locked / 60_000)} min`,
      );
    }
    const user = users.get(login.username);
    const passwordOk = await deps.verifyPassword(
      login.password,
      user?.password ?? DUMMY_HASH,
    );
    const step = user
      ? verifyTotp(user.totp_secret, login.totp, Math.floor(now / 1000))
      : null;
    const replay =
      user !== undefined &&
      step !== null &&
      (usedSteps.get(user.name) ?? -1) >= step;
    if (!user || !passwordOk || step === null || replay) {
      const lockedNow = keys.map((key) => limiter.fail(key, now)).some(Boolean);
      deps.audit.append({
        kind: 'auth',
        actor: user ? user.name : 'unknown',
        what: `Failed sign-in for "${login.username}"${lockedNow ? ', locked 5 min' : ''}`,
        facts: [
          ['From', network],
          ['Reason', replay ? 'code already used' : 'wrong credentials'],
        ],
      });
      return fail(401, 'wrong user name, password or code');
    }
    for (const key of keys) limiter.succeed(key);
    usedSteps.set(user.name, step);
    const session = deps.sessions.create(user.name, user.role, now);
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
        ['From', network],
        ['Role', user.role],
      ],
    });
    return send(c, sessionSchema, sessionJson(session));
  });

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
