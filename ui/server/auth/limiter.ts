// Sign-in throttling: after `limit` failures for one key (a user name or
// a client prefix) within `windowMs`, the key is locked for `lockMs`.

export interface LimiterOptions {
  limit: number;
  windowMs: number;
  lockMs: number;
}

interface Entry {
  failures: number[];
  lockedUntil: number;
}

const MAX_KEYS = 50_000;

export class FailureLimiter {
  private readonly entries = new Map<string, Entry>();
  private readonly options: LimiterOptions;

  constructor(options: LimiterOptions) {
    this.options = options;
  }

  // Milliseconds until `key` may try again; 0 when not locked.
  lockedFor(key: string, now: number): number {
    const entry = this.entries.get(key);
    return entry && entry.lockedUntil > now ? entry.lockedUntil - now : 0;
  }

  // Records a failure; returns true when it locked the key.
  fail(key: string, now: number): boolean {
    if (this.entries.size >= MAX_KEYS) this.sweep(now);
    const entry = this.entries.get(key) ?? { failures: [], lockedUntil: 0 };
    entry.failures = entry.failures.filter(
      (time) => now - time < this.options.windowMs,
    );
    entry.failures.push(now);
    let locked = false;
    if (entry.failures.length >= this.options.limit) {
      entry.lockedUntil = now + this.options.lockMs;
      entry.failures = [];
      locked = true;
    }
    this.entries.set(key, entry);
    return locked;
  }

  succeed(key: string): void {
    this.entries.delete(key);
  }

  private sweep(now: number): void {
    for (const [key, entry] of this.entries) {
      const recent = entry.failures.some(
        (time) => now - time < this.options.windowMs,
      );
      if (!recent && entry.lockedUntil <= now) this.entries.delete(key);
    }
  }
}
