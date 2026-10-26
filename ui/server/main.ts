// larpguard-console: the console's BFF.
//
//   larpguard-console serve --config /etc/larpguard/console.yaml
//   larpguard-console hash-password        (reads the password from stdin)
//   larpguard-console totp-secret <user>   (prints a secret and its URI)

import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { serve } from '@hono/node-server';

import { createAnalytics } from './analytics/analytics.ts';
import { createClickHouseRun } from './analytics/clickhouse.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { PasskeyStore } from './auth/passkeys.ts';
import { hashPassword, verifyPassword } from './auth/password.ts';
import { SessionStore } from './auth/sessions.ts';
import { newTotpSecret, otpauthUri } from './auth/totp.ts';
import { loadConsoleConfig } from './config.ts';
import { createAdminClient } from './gateway/admin.ts';
import { createMetricsClient } from './gateway/metrics.ts';
import { createTraefikClient } from './gateway/traefik.ts';

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let text = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk: string) => (text += chunk));
    process.stdin.on('end', () => {
      resolve(text);
    });
    process.stdin.on('error', reject);
  });
}

function serveCommand(argv: string[]): void {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string', default: '/etc/larpguard/console.yaml' },
      static: { type: 'string' },
    },
  });
  const config = loadConsoleConfig(values.config);
  const clickhouse =
    config.clickhouse && createClickHouseRun(config.clickhouse);
  const admin = createAdminClient(config.gateway.admin_socket);
  const app = createApp({
    config,
    admin,
    analytics:
      config.clickhouse && clickhouse
        ? createAnalytics(config.clickhouse.database, clickhouse.run)
        : null,
    metrics: createMetricsClient(config.gateway.metrics_url),
    traefik: config.traefik_api
      ? createTraefikClient(config.traefik_api)
      : null,
    // Each entry is sealed by the gateway's key when it has one.
    audit: new AuditLog(config.audit_log, Date.now, {
      sign: (hash) => admin.signAudit(hash),
      key: () => admin.auditKey(),
    }),
    sessions: new SessionStore({
      idleMs: config.session.idle,
      maxMs: config.session.max,
    }),
    passkeys:
      config.passkeys_file === null
        ? null
        : new PasskeyStore(config.passkeys_file),
    now: Date.now,
    staticRoot:
      values.static ?? fileURLToPath(new URL('../web', import.meta.url)),
    verifyPassword,
  });
  const server = serve({
    fetch: app.fetch,
    hostname: config.listen.host,
    port: config.listen.port,
  });
  console.log(
    `larpguard-console on ${config.listen.host}:${config.listen.port} for ${config.public_origin}`,
  );
  const stop = () => {
    server.close();
    void clickhouse?.close();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

async function main(): Promise<void> {
  const [command = 'serve', ...rest] = process.argv.slice(2);
  switch (command) {
    case 'serve':
      serveCommand(rest);
      return;
    case 'hash-password': {
      const password = (await readStdin()).replace(/\r?\n$/, '');
      if (password.length < 12) {
        throw new Error('use a password of at least 12 characters');
      }
      console.log(await hashPassword(password));
      return;
    }
    case 'totp-secret': {
      const user = rest[0];
      if (!user) throw new Error('usage: larpguard-console totp-secret <user>');
      const secret = newTotpSecret();
      console.log(`totp_secret: ${secret}`);
      console.log(otpauthUri(secret, user));
      return;
    }
    default:
      throw new Error(
        `unknown command ${command} (serve, hash-password, totp-secret)`,
      );
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
