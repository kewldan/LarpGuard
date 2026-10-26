// The console's configuration (console.yaml). Unknown keys are errors, as
// in the gateway's config, so a typo never falls back to a default.

import { readFileSync } from 'node:fs';

import { parse } from 'yaml';
import { z } from 'zod';

import { roleSchema } from '../shared/api.ts';

const durationPattern = /^(\d+)(ms|s|m|h|d)$/;
const unitMs: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

// "250ms", "30s", "30m", "12h", "7d" to milliseconds.
export function parseDuration(text: string): number | null {
  const match = durationPattern.exec(text);
  if (!match?.[1] || !match[2]) return null;
  const unit = unitMs[match[2]];
  return unit === undefined ? null : Number(match[1]) * unit;
}

const duration = z.string().transform((text, context) => {
  const ms = parseDuration(text);
  if (ms === null || ms <= 0) {
    context.addIssue({
      code: 'custom',
      message: 'expected a duration like 30m',
    });
    return z.NEVER;
  }
  return ms;
});

const listen = z.string().transform((text, context) => {
  const match = /^(.*):(\d{1,5})$/.exec(text);
  const port = Number(match?.[2]);
  if (!match?.[1] || port < 1 || port > 65535) {
    context.addIssue({ code: 'custom', message: 'expected host:port' });
    return z.NEVER;
  }
  return { host: match[1].replace(/^\[(.*)\]$/, '$1'), port };
});

const userSchema = z
  .object({
    name: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/),
    role: roleSchema,
    // From `larpguard-console hash-password`.
    password: z.string().startsWith('scrypt$'),
    // Base32 TOTP secret from `larpguard-console totp-secret`.
    totp_secret: z
      .string()
      .regex(/^[A-Z2-7]{16,}=*$/, 'base32 (A-Z, 2-7), at least 16 characters'),
  })
  .strict();

export const consoleConfigSchema = z
  .object({
    listen: listen.default({ host: '127.0.0.1', port: 9901 }),
    // The origin browsers use (https://console.example.com): mutating
    // requests must come from it, and cookies are Secure unless it is
    // http://localhost.
    public_origin: z.url(),
    gateway: z
      .object({
        admin_socket: z.string().default('/run/bot-shield/admin.sock'),
        metrics_url: z.url().default('http://127.0.0.1:9900'),
      })
      .strict()
      .default({
        admin_socket: '/run/bot-shield/admin.sock',
        metrics_url: 'http://127.0.0.1:9900',
      }),
    clickhouse: z
      .object({
        url: z.url().default('http://127.0.0.1:8123'),
        database: z.string().regex(/^\w+$/).default('bot_shield'),
        user: z.string().default('default'),
        password_file: z.string().optional(),
      })
      .strict()
      .nullable()
      .default(null),
    audit_log: z.string().min(1),
    // Users added by an admin in the console (written by the console);
    // null: only console.yaml's users, none can be added.
    users_file: z
      .string()
      .min(1)
      .nullable()
      .default('/var/lib/larpguard/users.json'),
    // Registered passkeys (written by the console); null turns passkeys off.
    passkeys_file: z
      .string()
      .min(1)
      .nullable()
      .default('/var/lib/larpguard/passkeys.json'),
    session: z
      .object({
        idle: duration.default(30 * 60_000),
        max: duration.default(12 * 3_600_000),
      })
      .strict()
      .default({ idle: 30 * 60_000, max: 12 * 3_600_000 }),
    users: z.array(userSchema).min(1),
  })
  .strict()
  .superRefine((config, context) => {
    const names = new Set<string>();
    for (const user of config.users) {
      if (names.has(user.name)) {
        context.addIssue({
          code: 'custom',
          message: `duplicate user ${user.name}`,
          path: ['users'],
        });
      }
      names.add(user.name);
    }
  });

export type ConsoleConfig = z.output<typeof consoleConfigSchema>;
export type ConsoleUser = ConsoleConfig['users'][number];

export function parseConsoleConfig(text: string): ConsoleConfig {
  const result = consoleConfigSchema.safeParse(parse(text));
  if (!result.success) {
    const problems = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new Error(`console config: ${problems}`);
  }
  return result.data;
}

export function loadConsoleConfig(path: string): ConsoleConfig {
  return parseConsoleConfig(readFileSync(path, 'utf8'));
}

// Cookies need Secure except on plain-HTTP localhost (development).
export function secureCookies(config: ConsoleConfig): boolean {
  const origin = new URL(config.public_origin);
  return !(
    origin.protocol === 'http:' &&
    ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
  );
}
