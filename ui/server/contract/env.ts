// Shared plumbing of the contract tests: finding what they run against,
// skipping (or failing under CONTRACT_REQUIRED=1) when it is missing, and
// small helpers for processes, ports and certificates.

import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { accessSync, constants, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = resolve(
  fileURLToPath(new URL('../../..', import.meta.url)),
);

// In CI a missing prerequisite is a failure, not a skip.
const REQUIRED = process.env['CONTRACT_REQUIRED'] === '1';

// Returns true when `missing` is undefined; otherwise reports why the suite
// is skipped (or throws when the prerequisites are required).
export function prerequisite(suite: string, missing: string | undefined) {
  if (missing === undefined) return true;
  const message = `${suite} contract skipped: ${missing}`;
  if (REQUIRED) throw new Error(`${message} (CONTRACT_REQUIRED=1)`);
  process.stderr.write(`${message}\n`);
  return false;
}

function executable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

// The gateway binary: BOT_SHIELD_BIN, else a build directory of the repo.
export function findGateway(): { binary: string; upstream: string } | string {
  const env = process.env['BOT_SHIELD_BIN'];
  const candidates =
    env === undefined
      ? ['build-contract', 'build'].map((dir) =>
          join(REPO, dir, 'src', 'bot-shield'),
        )
      : [resolve(env)];
  const binary = candidates.find(executable);
  if (binary === undefined) {
    return env === undefined
      ? `no gateway binary (build ${candidates.join(' or ')}, or set BOT_SHIELD_BIN)`
      : `BOT_SHIELD_BIN=${env} is not an executable`;
  }
  const upstream =
    process.env['BOT_SHIELD_FAKE_UPSTREAM'] ??
    join(binary, '..', '..', 'tests', 'bot_shield_fake_upstream');
  if (!executable(upstream)) {
    return `no fake upstream next to ${binary} (set BOT_SHIELD_FAKE_UPSTREAM)`;
  }
  return { binary, upstream };
}

export function findOpenssl(): string | undefined {
  for (const candidate of [
    '/opt/homebrew/opt/openssl@3/bin/openssl',
    '/usr/local/opt/openssl@3/bin/openssl',
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return 'openssl';
  } catch {
    return undefined;
  }
}

// Self-signed P-256 certificate for `names`; returns PEM paths.
export function makeCert(
  openssl: string,
  dir: string,
  name: string,
  names: string[],
): { cert: string; key: string } {
  const cert = join(dir, `${name}.crt`);
  const key = join(dir, `${name}.key`);
  execFileSync(
    openssl,
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      key,
      '-out',
      cert,
      '-days',
      '2',
      '-subj',
      `/CN=${names[0]}`,
      '-addext',
      `subjectAltName=${names.map((n) => `DNS:${n}`).join(',')}`,
    ],
    { stdio: 'ignore' },
  );
  return { cert, key };
}

export function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => {
        if (address === null || typeof address === 'string') {
          reject(new Error('no port'));
        } else {
          resolvePort(address.port);
        }
      });
    });
  });
}

// Polls `check` until it returns true or `timeoutMs` passes.
export async function waitFor(
  what: string,
  check: () => Promise<boolean>,
  timeoutMs = 20_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check().catch(() => false)) return;
    await new Promise((done) => setTimeout(done, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

// A child process whose output is kept for error messages.
export interface Child {
  process: ChildProcess;
  output: () => string;
  stop: () => Promise<void>;
}

export function startChild(command: string, args: string[]): Child {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  const keep = (chunk: Buffer) => {
    output = (output + chunk.toString()).slice(-20_000);
  };
  child.stdout?.on('data', keep);
  child.stderr?.on('data', keep);
  return {
    process: child,
    output: () => output,
    stop: () =>
      new Promise((done) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          done();
          return;
        }
        child.once('exit', () => done());
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5_000).unref();
      }),
  };
}
