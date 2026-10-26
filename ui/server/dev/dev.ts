// Development server: the BFF with an in-memory gateway and synthetic
// analytics (npm run dev:api, browser tests). Sign in as "dev" (operator)
// or "viewer" with password "dev-password-1" and the TOTP code of
// DEV_TOTP_SECRET. LG_FIXED_TIME (Unix ms) freezes the clock and the
// traffic, for repeatable screenshots.

import { serve } from '@hono/node-server';

import { createApp } from '../app.ts';
import { AuditLog } from '../audit.ts';
import { PasskeyStore } from '../auth/passkeys.ts';
import { SessionStore } from '../auth/sessions.ts';
import { parseConsoleConfig } from '../config.ts';
import type { MetricsApi } from '../gateway/metrics.ts';
import { createMockAdmin, MOCK_SHADOW_HOSTS } from './mock-admin.ts';
import { createMockAnalytics } from './mock-analytics.ts';
import { MockTraffic } from './mock-data.ts';
import { DEV_PASSWORD, DEV_TOTP_SECRET } from './users.ts';

const port = Number(process.env['LG_PORT'] ?? 9901);
const origin = process.env['LG_ORIGIN'] ?? 'http://localhost:5173';
const staticRoot = process.env['LG_STATIC'] ?? null;

const config = parseConsoleConfig(`
listen: 127.0.0.1:${port}
public_origin: ${origin}
audit_log: /dev/null
users:
  - name: dev
    role: operator
    password: scrypt$10$8$1$ZGV2LXNhbHQtMDEyMzQ1Ng==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    totp_secret: ${DEV_TOTP_SECRET}
  - name: viewer
    role: viewer
    password: scrypt$10$8$1$ZGV2LXNhbHQtMDEyMzQ1Ng==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    totp_secret: ${DEV_TOTP_SECRET}
`);

const fixed = process.env['LG_FIXED_TIME'];
const started = fixed ? Number(fixed) : Date.now();
const now = fixed ? () => started : () => Date.now();
const traffic = new MockTraffic(started, MOCK_SHADOW_HOSTS);
const events = traffic.events;
if (!fixed) {
  // New events every second, so live views move.
  setInterval(() => {
    traffic.extend(Date.now());
  }, 1000).unref();
}
const metrics: MetricsApi = {
  read: () => {
    // The synthetic events' rate over the last minute.
    const from = now() - 60_000;
    let recent = 0;
    for (
      let i = events.length - 1;
      i >= 0 && (events[i]?.ts ?? 0) >= from;
      i -= 1
    ) {
      recent += 1;
    }
    return Promise.resolve({
      healthy: true,
      metrics: new Map([
        ['bot_shield_xdp_attached', 1],
        ['bot_shield_xdp_packets_total{result="blocked"}', 41_200],
        ['bot_shield_attack_auto_activations_total', 1],
      ]),
      rps: recent / 60,
    });
  },
};

const admin = createMockAdmin(now);
const app = createApp({
  config,
  admin,
  analytics: createMockAnalytics(events, now),
  metrics,
  audit: new AuditLog(null, now, {
    sign: (hash) => admin.signAudit(hash),
    key: () => admin.auditKey(),
  }),
  sessions: new SessionStore({
    idleMs: config.session.idle,
    maxMs: config.session.max,
  }),
  // In memory: passkeys registered in development vanish on restart.
  passkeys: new PasskeyStore(null),
  now,
  staticRoot,
  // Development only: one fixed password for both users.
  verifyPassword: (password) => Promise.resolve(password === DEV_PASSWORD),
});

serve({ fetch: app.fetch, hostname: '127.0.0.1', port });
console.log(
  `dev console API on 127.0.0.1:${port} (origin ${origin}), ${events.length} synthetic events`,
);
