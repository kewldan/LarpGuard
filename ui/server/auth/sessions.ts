// Server-side sessions in memory: random 256-bit ids in a cookie, an idle
// timeout and an absolute lifetime. One console process, so no store.

import { randomBytes, timingSafeEqual } from 'node:crypto';

import type { Role } from '../../shared/domain.ts';

export interface SessionData {
  id: string;
  user: string;
  role: Role;
  csrf: string;
  createdAt: number;
  lastSeen: number;
}

export interface SessionTimes {
  idleMs: number;
  maxMs: number;
}

const MAX_SESSIONS = 10_000;

export class SessionStore {
  private readonly sessions = new Map<string, SessionData>();
  private readonly times: SessionTimes;

  constructor(times: SessionTimes) {
    this.times = times;
  }

  create(user: string, role: Role, now: number): SessionData {
    this.sweep(now);
    if (this.sessions.size >= MAX_SESSIONS) {
      // Oldest first (Map keeps insertion order).
      const oldest = this.sessions.keys().next();
      if (!oldest.done) this.sessions.delete(oldest.value);
    }
    const session: SessionData = {
      id: randomBytes(32).toString('base64url'),
      user,
      role,
      csrf: randomBytes(32).toString('base64url'),
      createdAt: now,
      lastSeen: now,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  // The live session for a cookie value, touched; null when unknown or
  // expired.
  get(id: string | undefined, now: number): SessionData | null {
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session) return null;
    if (this.expired(session, now)) {
      this.sessions.delete(id);
      return null;
    }
    session.lastSeen = now;
    return session;
  }

  expiresAt(session: SessionData): number {
    return Math.min(
      session.lastSeen + this.times.idleMs,
      session.createdAt + this.times.maxMs,
    );
  }

  destroy(id: string): void {
    this.sessions.delete(id);
  }

  // Ends every session of a user (removed from the config, password changed).
  destroyUser(user: string): void {
    for (const [id, session] of this.sessions) {
      if (session.user === user) this.sessions.delete(id);
    }
  }

  // Live sessions of a user (the users screen).
  countUser(user: string, now: number): number {
    let count = 0;
    for (const session of this.sessions.values()) {
      if (session.user === user && !this.expired(session, now)) count += 1;
    }
    return count;
  }

  get size(): number {
    return this.sessions.size;
  }

  private expired(session: SessionData, now: number): boolean {
    return now >= this.expiresAt(session);
  }

  private sweep(now: number): void {
    for (const [id, session] of this.sessions) {
      if (this.expired(session, now)) this.sessions.delete(id);
    }
  }
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
