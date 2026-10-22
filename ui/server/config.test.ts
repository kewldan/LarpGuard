import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { parseConsoleConfig, parseDuration, secureCookies } from './config.ts';

const minimal = `
public_origin: https://console.example.com
audit_log: /var/lib/larpguard/audit.jsonl
users:
  - name: ops
    role: operator
    password: scrypt$17$8$1$AAAA$BBBB
    totp_secret: JBSWY3DPEHPK3PXP
`;

describe('console config', () => {
  it('parses the example in deploy/', () => {
    const config = parseConsoleConfig(
      readFileSync('../deploy/console.yaml', 'utf8'),
    );
    expect(config.listen).toEqual({ host: '127.0.0.1', port: 9901 });
    expect(config.clickhouse?.user).toBe('console');
    expect(config.session).toEqual({ idle: 30 * 60_000, max: 12 * 3_600_000 });
  });

  it('fills defaults and decides on secure cookies', () => {
    const config = parseConsoleConfig(minimal);
    expect(config.gateway.admin_socket).toBe('/run/bot-shield/admin.sock');
    expect(config.clickhouse).toBeNull();
    expect(config.passkeys_file).toBe('/var/lib/larpguard/passkeys.json');
    expect(
      parseConsoleConfig(`${minimal}passkeys_file: null\n`).passkeys_file,
    ).toBeNull();
    expect(secureCookies(config)).toBe(true);
    expect(
      secureCookies(
        parseConsoleConfig(
          minimal.replace(
            'https://console.example.com',
            'http://localhost:5173',
          ),
        ),
      ),
    ).toBe(false);
  });

  it('refuses unknown keys, duplicate users and bad values', () => {
    expect(() => parseConsoleConfig(`${minimal}listn: 1\n`)).toThrow(
      /listn|Unrecognized/,
    );
    expect(() =>
      parseConsoleConfig(
        `${minimal}  - name: ops\n    role: viewer\n    password: scrypt$x\n    totp_secret: JBSWY3DPEHPK3PXP\n`,
      ),
    ).toThrow(/duplicate user ops/);
    expect(() =>
      parseConsoleConfig(minimal.replace('operator', 'root')),
    ).toThrow(/role/);
    expect(() =>
      parseConsoleConfig(minimal.replace('JBSWY3DPEHPK3PXP', 'short')),
    ).toThrow(/base32/);
    expect(() => parseConsoleConfig(`${minimal}listen: nope\n`)).toThrow(
      /host:port/,
    );
  });

  it('parses durations', () => {
    expect(parseDuration('250ms')).toBe(250);
    expect(parseDuration('30m')).toBe(1_800_000);
    expect(parseDuration('7d')).toBe(604_800_000);
    expect(parseDuration('5')).toBeNull();
  });
});
