// The audit log (the design's "Decision log"): every change made through
// the console and every sign-in, appended to a JSONL file. Each line
// carries the SHA-256 of the previous one, so editing or deleting lines
// breaks the chain (`intact`). With a signer, each entry's hash is also
// signed by the gateway's Ed25519 key (admin.audit_key_file), which the
// console never holds: a "seal" line follows the entry, and a forged or
// rewritten entry has no valid seal.

import {
  createHash,
  createPublicKey,
  type KeyObject,
  randomBytes,
  verify,
} from 'node:crypto';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';

import type { AuditEntry, AuditKind, AuditSignature } from '../shared/api.ts';

interface StoredEntry {
  id: string;
  ts: number;
  kind: AuditKind;
  actor: string;
  what: string;
  before?: unknown;
  after?: unknown;
  facts: [string, string][];
  reverts?: string;
  prev: string;
  hash: string;
}

export type NewAuditEntry = Omit<StoredEntry, 'id' | 'ts' | 'prev' | 'hash'>;

// The gateway's signature of an entry's hash.
interface Seal {
  seal: string;
  signature: string;
  key_id: string;
}

export interface AuditSigner {
  // Null when the gateway does not sign (or cannot be reached now).
  sign(hash: string): Promise<{ signature: string; key_id: string } | null>;
  key(): Promise<{ key_id: string; public_key: string } | null>;
}

// What GET /api/audit says about signatures: the gateway's key, and how
// many entries carry a valid seal from it.
export interface SigningState {
  key_id: string;
  valid: number;
  invalid: number;
  missing: number;
}

const DOMAIN = 'larpguard-audit-v1\n';
// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

export function ed25519Key(publicKey: string): KeyObject {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI, Buffer.from(publicKey, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
}

export function verifySeal(
  hash: string,
  signature: string,
  key: KeyObject,
): boolean {
  try {
    return verify(
      null,
      Buffer.from(DOMAIN + hash),
      key,
      Buffer.from(signature, 'base64url'),
    );
  } catch {
    return false;
  }
}

const GENESIS = '0'.repeat(64);
// Entries kept in memory for the screen; the file keeps everything.
const MEMORY_LIMIT = 5000;

function digest(entry: Omit<StoredEntry, 'hash'>): string {
  return createHash('sha256').update(JSON.stringify(entry)).digest('hex');
}

export class AuditLog {
  private readonly path: string | null;
  private readonly now: () => number;
  private readonly signer: AuditSigner | null;
  private entries: StoredEntry[] = [];
  private seals = new Map<string, Seal>();
  // Verified seals by "hash|key": checking 5000 signatures on every view
  // would be wasted work.
  private verified = new Map<string, boolean>();
  private sealing: Promise<void> = Promise.resolve();
  private last = GENESIS;
  private intactChain = true;

  // `path` null: memory only (tests, development).
  constructor(
    path: string | null,
    now: () => number = Date.now,
    signer: AuditSigner | null = null,
  ) {
    this.path = path;
    this.now = now;
    this.signer = signer;
    if (path !== null && existsSync(path)) this.load(path);
  }

  get intact(): boolean {
    return this.intactChain;
  }

  append(entry: NewAuditEntry): StoredEntry {
    const body = {
      id: randomBytes(8).toString('hex'),
      ts: this.now(),
      ...entry,
      prev: this.last,
    };
    const stored: StoredEntry = { ...body, hash: digest(body) };
    if (this.path !== null) {
      appendFileSync(this.path, `${JSON.stringify(stored)}\n`, { mode: 0o600 });
    }
    this.last = stored.hash;
    this.entries.push(stored);
    if (this.entries.length > MEMORY_LIMIT) this.entries.shift();
    if (this.signer) this.seal(this.signer, stored.hash);
    return stored;
  }

  // Resolves once every seal asked for so far is written (tests).
  settled(): Promise<void> {
    return this.sealing;
  }

  private seal(signer: AuditSigner, hash: string): void {
    // In order, and never failing the change that was logged: without the
    // gateway the entry stays unsigned.
    this.sealing = this.sealing.then(async () => {
      const signed = await signer.sign(hash).catch(() => null);
      if (!signed) return;
      const seal: Seal = { seal: hash, ...signed };
      if (this.path !== null) {
        appendFileSync(this.path, `${JSON.stringify(seal)}\n`, {
          mode: 0o600,
        });
      }
      this.seals.set(hash, seal);
    });
  }

  // Seals checked against the gateway's current key; null when the
  // gateway does not sign.
  async signatures(): Promise<{
    state: SigningState;
    of: (hash: string) => AuditSignature;
  } | null> {
    const key = this.signer ? await this.signer.key().catch(() => null) : null;
    if (!key) return null;
    const publicKey = ed25519Key(key.public_key);
    const of = (hash: string): AuditSignature => {
      const seal = this.seals.get(hash);
      if (!seal) return 'missing';
      if (seal.key_id !== key.key_id) return 'other_key';
      const id = `${hash}|${key.key_id}`;
      let ok = this.verified.get(id);
      if (ok === undefined) {
        ok = verifySeal(hash, seal.signature, publicKey);
        this.verified.set(id, ok);
      }
      return ok ? 'valid' : 'invalid';
    };
    const state: SigningState = {
      key_id: key.key_id,
      valid: 0,
      invalid: 0,
      missing: 0,
    };
    for (const entry of this.entries) {
      const result = of(entry.hash);
      if (result === 'valid') state.valid += 1;
      else if (result === 'missing') state.missing += 1;
      else state.invalid += 1;
    }
    return { state, of };
  }

  find(id: string): StoredEntry | undefined {
    return this.entries.find((entry) => entry.id === id);
  }

  // Newest first, as the API shows them; `signature` from signatures().
  list(
    isRevertible: (entry: StoredEntry) => boolean,
    signature?: (hash: string) => AuditSignature,
  ): AuditEntry[] {
    const reverted = new Set(
      this.entries.flatMap((entry) => (entry.reverts ? [entry.reverts] : [])),
    );
    return this.entries
      .slice()
      .reverse()
      .map((entry) => ({
        id: entry.id,
        ts: entry.ts,
        kind: entry.kind,
        actor: entry.actor,
        what: entry.what,
        ...(entry.before === undefined ? {} : { before: entry.before }),
        ...(entry.after === undefined ? {} : { after: entry.after }),
        facts: entry.facts,
        ...(entry.reverts === undefined ? {} : { reverts: entry.reverts }),
        revertible: !reverted.has(entry.id) && isRevertible(entry),
        ...(signature ? { signature: signature(entry.hash) } : {}),
      }));
  }

  isReverted(id: string): boolean {
    return this.entries.some((entry) => entry.reverts === id);
  }

  private load(path: string): void {
    let previous = GENESIS;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (line.trim() === '') continue;
      let entry: StoredEntry;
      try {
        const parsed = JSON.parse(line) as StoredEntry | Seal;
        if ('seal' in parsed) {
          // Seals sit outside the chain: each signs one entry's hash.
          this.seals.set(parsed.seal, parsed);
          continue;
        }
        entry = parsed;
      } catch {
        this.intactChain = false;
        continue;
      }
      const { hash, ...body } = entry;
      if (entry.prev !== previous || digest(body) !== hash) {
        this.intactChain = false;
      }
      previous = hash;
      this.entries.push(entry);
      if (this.entries.length > MEMORY_LIMIT) this.entries.shift();
    }
    this.last = previous;
  }
}

export type { StoredEntry };
