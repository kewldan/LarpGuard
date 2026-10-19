import { describe, expect, it } from 'vitest';

import { FailureLimiter } from './limiter.ts';
import {
  hashPassword,
  isValidPasswordHash,
  verifyPassword,
} from './password.ts';
import { SessionStore, safeEqual } from './sessions.ts';
import {
  base32Decode,
  base32Encode,
  newTotpSecret,
  otpauthUri,
  totpAt,
  verifyTotp,
} from './totp.ts';

describe('totp', () => {
  // RFC 6238, appendix B (SHA-1, 8 digits).
  const secret = Buffer.from('12345678901234567890', 'ascii');
  it.each([
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ])('matches the RFC test vector at %i', (time, code) => {
    expect(totpAt(secret, time, 8)).toBe(code);
  });

  it('round-trips base32', () => {
    expect(base32Encode(Buffer.from('12345678901234567890'))).toBe(
      'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    );
    expect(
      base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').toString('ascii'),
    ).toBe('12345678901234567890');
    expect(() => base32Decode('01')).toThrow();
  });

  it('accepts one step of drift and returns the step', () => {
    const encoded = base32Encode(secret);
    const now = 1_700_000_000;
    const step = Math.floor(now / 30);
    expect(verifyTotp(encoded, totpAt(secret, now), now)).toBe(step);
    expect(verifyTotp(encoded, totpAt(secret, now - 30), now)).toBe(step - 1);
    expect(verifyTotp(encoded, totpAt(secret, now + 30), now)).toBe(step + 1);
    expect(verifyTotp(encoded, totpAt(secret, now - 90), now)).toBeNull();
    expect(verifyTotp(encoded, 'abcdef', now)).toBeNull();
  });

  it('makes secrets and provisioning URIs', () => {
    const generated = newTotpSecret();
    expect(generated).toMatch(/^[A-Z2-7]{32}$/);
    expect(otpauthUri(generated, 'd.ops')).toBe(
      `otpauth://totp/LarpGuard%3Ad.ops?secret=${generated}&issuer=LarpGuard`,
    );
  });
});

describe('password', () => {
  it('hashes and verifies with scrypt', async () => {
    const encoded = await hashPassword('correct horse', 10);
    expect(encoded).toMatch(/^scrypt\$10\$8\$1\$[^$]+\$[^$]+$/);
    expect(isValidPasswordHash(encoded)).toBe(true);
    expect(await verifyPassword('correct horse', encoded)).toBe(true);
    expect(await verifyPassword('wrong horse', encoded)).toBe(false);
  });

  it('rejects malformed hashes', async () => {
    expect(isValidPasswordHash('scrypt$99$8$1$AAAA$AAAA')).toBe(false);
    expect(isValidPasswordHash('bcrypt$x')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$10$8$1$c2FsdA==$AAAA')).toBe(
      false,
    );
  });
});

describe('sessions', () => {
  it('expires on idle and on the absolute limit', () => {
    const store = new SessionStore({ idleMs: 1000, maxMs: 5000 });
    const session = store.create('d.ops', 'operator', 0);
    expect(session.id).toHaveLength(43);
    expect(store.get(session.id, 900)).not.toBeNull();
    expect(store.get(session.id, 1800)).not.toBeNull(); // Touched at 900.
    expect(store.get(session.id, 2900)).toBeNull(); // Idle.

    const long = store.create('d.ops', 'operator', 0);
    for (let t = 800; t < 5000; t += 800) {
      expect(store.get(long.id, t)).not.toBeNull();
    }
    expect(store.get(long.id, 5000)).toBeNull(); // Absolute.
    expect(store.get(undefined, 0)).toBeNull();
  });

  it('destroys one or all sessions of a user', () => {
    const store = new SessionStore({ idleMs: 1000, maxMs: 5000 });
    const a = store.create('a', 'viewer', 0);
    store.create('a', 'viewer', 0);
    const b = store.create('b', 'viewer', 0);
    store.destroy(b.id);
    expect(store.get(b.id, 1)).toBeNull();
    store.destroyUser('a');
    expect(store.get(a.id, 1)).toBeNull();
    expect(store.size).toBe(0);
  });

  it('compares tokens', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'ab')).toBe(false);
  });
});

describe('limiter', () => {
  it('locks after the limit within the window', () => {
    const limiter = new FailureLimiter({
      limit: 3,
      windowMs: 1000,
      lockMs: 5000,
    });
    expect(limiter.fail('u', 0)).toBe(false);
    expect(limiter.fail('u', 100)).toBe(false);
    expect(limiter.lockedFor('u', 100)).toBe(0);
    expect(limiter.fail('u', 200)).toBe(true);
    expect(limiter.lockedFor('u', 300)).toBe(4900);
    expect(limiter.lockedFor('u', 5200)).toBe(0);
    // Old failures fall out of the window.
    limiter.fail('v', 0);
    limiter.fail('v', 100);
    expect(limiter.fail('v', 1500)).toBe(false);
    limiter.succeed('v');
    expect(limiter.lockedFor('v', 1500)).toBe(0);
  });
});
