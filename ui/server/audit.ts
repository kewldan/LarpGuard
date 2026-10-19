// The audit log (the design's "Decision log"): every change made through
// the console and every sign-in, appended to a JSONL file. Each line
// carries the SHA-256 of the previous one, so editing or deleting lines
// breaks the chain (`intact`).

import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';

import type { AuditEntry, AuditKind } from '../shared/api.ts';

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

const GENESIS = '0'.repeat(64);
// Entries kept in memory for the screen; the file keeps everything.
const MEMORY_LIMIT = 5000;

function digest(entry: Omit<StoredEntry, 'hash'>): string {
  return createHash('sha256').update(JSON.stringify(entry)).digest('hex');
}

export class AuditLog {
  private readonly path: string | null;
  private readonly now: () => number;
  private entries: StoredEntry[] = [];
  private last = GENESIS;
  private intactChain = true;

  // `path` null: memory only (tests, development).
  constructor(path: string | null, now: () => number = Date.now) {
    this.path = path;
    this.now = now;
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
    return stored;
  }

  find(id: string): StoredEntry | undefined {
    return this.entries.find((entry) => entry.id === id);
  }

  // Newest first, as the API shows them.
  list(isRevertible: (entry: StoredEntry) => boolean): AuditEntry[] {
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
        entry = JSON.parse(line) as StoredEntry;
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
