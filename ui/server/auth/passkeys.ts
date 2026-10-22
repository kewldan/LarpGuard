// Passkeys (WebAuthn credentials) of the console's users, kept in a JSON
// file next to the audit log (console.yaml is read-only), and the
// single-use challenges of registration and sign-in ceremonies.

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

import { z } from 'zod';

const passkeySchema = z
  .object({
    // Credential id, base64url.
    id: z.string().min(1).max(1024),
    user: z.string(),
    name: z.string(),
    // COSE public key, base64url.
    public_key: z.string().min(1),
    counter: z.number().int().nonnegative(),
    transports: z.array(z.string()),
    created_at: z.number(),
    last_used_at: z.number().nullable(),
  })
  .strict();
export type StoredPasskey = z.infer<typeof passkeySchema>;

const fileSchema = z
  .object({ version: z.literal(1), passkeys: z.array(passkeySchema) })
  .strict();

export const MAX_PASSKEYS_PER_USER = 20;

export class PasskeyStore {
  private readonly path: string | null;
  private passkeys: StoredPasskey[];

  // `path` null: memory only (development and tests).
  constructor(path: string | null) {
    this.path = path;
    this.passkeys =
      path !== null && existsSync(path)
        ? fileSchema.parse(JSON.parse(readFileSync(path, 'utf8'))).passkeys
        : [];
  }

  forUser(user: string): StoredPasskey[] {
    return this.passkeys.filter((passkey) => passkey.user === user);
  }

  find(id: string): StoredPasskey | undefined {
    return this.passkeys.find((passkey) => passkey.id === id);
  }

  add(passkey: StoredPasskey): void {
    if (this.find(passkey.id)) throw new Error('passkey already registered');
    this.save([...this.passkeys, passkey]);
  }

  // Only the owner's: returns the removed passkey or null.
  remove(user: string, id: string): StoredPasskey | null {
    const passkey = this.find(id);
    if (!passkey || passkey.user !== user) return null;
    this.save(this.passkeys.filter((other) => other.id !== id));
    return passkey;
  }

  used(id: string, counter: number, now: number): void {
    this.save(
      this.passkeys.map((passkey) =>
        passkey.id === id
          ? { ...passkey, counter, last_used_at: now }
          : passkey,
      ),
    );
  }

  // Written to a temporary file and renamed, so a crash never leaves half
  // a file; memory changes only once the file is written.
  private save(passkeys: StoredPasskey[]): void {
    if (this.path !== null) {
      const temporary = `${this.path}.${randomBytes(6).toString('hex')}.tmp`;
      writeFileSync(
        temporary,
        `${JSON.stringify({ version: 1, passkeys }, null, 2)}\n`,
        { mode: 0o600 },
      );
      renameSync(temporary, this.path);
    }
    this.passkeys = passkeys;
  }
}

const CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_CHALLENGES = 10_000;

// Challenges by ceremony key; each can be taken once, within five minutes.
export class ChallengeStore {
  private readonly challenges = new Map<
    string,
    { challenge: string; expires: number }
  >();

  put(key: string, challenge: string, now: number): void {
    if (this.challenges.size >= MAX_CHALLENGES) this.sweep(now);
    if (this.challenges.size >= MAX_CHALLENGES) {
      const oldest = this.challenges.keys().next();
      if (!oldest.done) this.challenges.delete(oldest.value);
    }
    this.challenges.delete(key);
    this.challenges.set(key, { challenge, expires: now + CHALLENGE_TTL_MS });
  }

  take(key: string, now: number): string | null {
    const entry = this.challenges.get(key);
    this.challenges.delete(key);
    return entry && entry.expires > now ? entry.challenge : null;
  }

  private sweep(now: number): void {
    for (const [key, entry] of this.challenges) {
      if (entry.expires <= now) this.challenges.delete(key);
    }
  }
}
