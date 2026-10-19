// Development server: the BFF with an in-memory gateway and synthetic
// analytics (npm run dev, browser tests). Sign in as "dev" with password
// "dev-password-1" and the TOTP code of DEV_TOTP_SECRET.

import { serve } from '@hono/node-server';

import { createApp } from '../app.ts';
import { AuditLog } from '../audit.ts';
import { SessionStore } from '../auth/sessions.ts';
import { parseConsoleConfig } from '../config.ts';
import type { MetricsApi } from '../gateway/metrics.ts';
import { createMockAdmin, MOCK_SHADOW_HOSTS } from './mock-admin.ts';
import { createMockAnalytics } from './mock-analytics.ts';
import { generateEvents } from './mock-data.ts';

export const DEV_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
export const DEV_PASSWORD = 'dev-password-1';

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

const started = Date.now();
const now = () => Date.now();
const events = generateEvents(started, MOCK_SHADOW_HOSTS);
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

const app = createApp({
  config,
  admin: createMockAdmin(now),
  analytics: createMockAnalytics(events, now),
  metrics,
  audit: new AuditLog(null),
  sessions: new SessionStore({
    idleMs: config.session.idle,
    maxMs: config.session.max,
  }),
  now,
  staticRoot,
  // Development only: one fixed password for both users.
  verifyPassword: (password) => Promise.resolve(password === DEV_PASSWORD),
});

serve({ fetch: app.fetch, hostname: '127.0.0.1', port });
console.log(
  `dev console API on 127.0.0.1:${port} (origin ${origin}), ${events.length} synthetic events`,
);
