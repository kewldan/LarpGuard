// What the routes use. main.ts builds the real ones; tests and dev mode
// pass fakes.

import type { HttpBindings } from '@hono/node-server';

import type { Analytics } from './analytics/analytics.ts';
import type { AuditLog } from './audit.ts';
import type { PasskeyStore } from './auth/passkeys.ts';
import type { SessionData, SessionStore } from './auth/sessions.ts';
import type { ConsoleConfig } from './config.ts';
import type { AdminApi } from './gateway/admin.ts';
import type { MetricsApi } from './gateway/metrics.ts';
import type { TraefikApi } from './gateway/traefik.ts';

export interface Deps {
  config: ConsoleConfig;
  admin: AdminApi;
  // Null: no ClickHouse configured; analytics screens say so.
  analytics: Analytics | null;
  metrics: MetricsApi;
  // Traefik's API (routers and services); null when not configured.
  traefik?: TraefikApi | null;
  audit: AuditLog;
  sessions: SessionStore;
  // Null: passkeys are off (passkeys_file: null).
  passkeys: PasskeyStore | null;
  now: () => number;
  // Built SPA (index.html and assets); null: API only (development).
  staticRoot: string | null;
  // Password check; injectable so tests skip scrypt's cost.
  verifyPassword: (password: string, hash: string) => Promise<boolean>;
}

export interface AppEnv {
  // Absent under app.request() in tests.
  Bindings: Partial<HttpBindings>;
  Variables: {
    session: SessionData;
    deps: Deps;
  };
}
