import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AuditLog, type AuditSigner } from './audit.ts';
import { createMockAdmin } from './dev/mock-admin.ts';

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true });
});

function logFile(): string {
  const dir = mkdtempSync(join(tmpdir(), 'lg-audit-'));
  dirs.push(dir);
  return join(dir, 'audit.jsonl');
}

function gatewaySigner(): AuditSigner {
  const admin = createMockAdmin(() => 0);
  return {
    sign: (hash) => admin.signAudit(hash),
    key: () => admin.auditKey(),
  };
}

const entry = (what: string) => ({
  kind: 'list' as const,
  actor: 'ops',
  what,
  facts: [] as [string, string][],
});

describe('AuditLog seals', () => {
  it('has the gateway sign each entry, and survives a restart', async () => {
    const path = logFile();
    const signer = gatewaySigner();
    const log = new AuditLog(path, () => 1, signer);
    log.append(entry('first'));
    log.append(entry('second'));
    await log.settled();
    const signed = await log.signatures();
    expect(signed?.state).toMatchObject({ valid: 2, invalid: 0, missing: 0 });
    expect(log.list(() => false, signed?.of)[0]?.signature).toBe('valid');

    const reopened = new AuditLog(path, () => 1, signer);
    expect(reopened.intact).toBe(true);
    expect((await reopened.signatures())?.state.valid).toBe(2);
  });

  it('flags a rewritten entry whose chain was rebuilt', async () => {
    const path = logFile();
    const signer = gatewaySigner();
    const log = new AuditLog(path, () => 1, signer);
    log.append(entry('blocked 203.0.113.0/24'));
    await log.settled();
    // Someone with the console's files rewrites the entry and recomputes
    // its hash: the chain checks out again, the gateway's seal does not.
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    const original = JSON.parse(lines[0] ?? '{}') as Record<string, unknown>;
    const body: Record<string, unknown> = { ...original, what: 'nothing' };
    delete body['hash'];
    const hash = createHash('sha256')
      .update(JSON.stringify(body))
      .digest('hex');
    const seal = JSON.parse(lines[1] ?? '{}') as Record<string, unknown>;
    writeFileSync(
      path,
      `${JSON.stringify({ ...body, hash })}\n${JSON.stringify({ ...seal, seal: hash })}\n`,
    );
    const reopened = new AuditLog(path, () => 1, signer);
    expect(reopened.intact).toBe(true);
    expect((await reopened.signatures())?.state).toMatchObject({
      valid: 0,
      invalid: 1,
    });
  });

  it('keeps logging without the gateway', async () => {
    const log = new AuditLog(null, () => 1, {
      sign: () => Promise.reject(new Error('socket gone')),
      key: () => Promise.resolve(null),
    });
    log.append(entry('offline'));
    await log.settled();
    expect(await log.signatures()).toBeNull();
    expect(log.list(() => false)[0]?.what).toBe('offline');
  });
});
