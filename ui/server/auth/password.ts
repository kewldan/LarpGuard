// Password hashes: scrypt from node:crypto, encoded as
// "scrypt$<log2 N>$<r>$<p>$<salt base64>$<hash base64>".

import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const KEY_LENGTH = 32;
const DEFAULT_LOG_N = 17; // N = 131072: ~0.2-0.4 s, 128 MiB.
const DEFAULT_R = 8;
const DEFAULT_P = 1;

function derive(
  password: string,
  salt: Buffer,
  logN: number,
  r: number,
  p: number,
): Promise<Buffer> {
  const N = 2 ** logN;
  // scrypt needs 128 * N * r bytes; allow it with some headroom.
  const maxmem = 128 * N * r * 2;
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KEY_LENGTH, { N, r, p, maxmem }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

export async function hashPassword(
  password: string,
  logN = DEFAULT_LOG_N,
): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, logN, DEFAULT_R, DEFAULT_P);
  return [
    'scrypt',
    logN,
    DEFAULT_R,
    DEFAULT_P,
    salt.toString('base64'),
    key.toString('base64'),
  ].join('$');
}

interface Parsed {
  logN: number;
  r: number;
  p: number;
  salt: Buffer;
  key: Buffer;
}

function parseHash(encoded: string): Parsed | null {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const [, logN, r, p, salt, key] = parts.map((part, i) =>
    i >= 1 && i <= 3 ? Number(part) : part,
  ) as [string, number, number, number, string, string];
  if (
    !Number.isInteger(logN) ||
    logN < 10 ||
    logN > 22 ||
    !Number.isInteger(r) ||
    r < 1 ||
    r > 32 ||
    !Number.isInteger(p) ||
    p < 1 ||
    p > 16
  ) {
    return null;
  }
  const saltBytes = Buffer.from(salt, 'base64');
  const keyBytes = Buffer.from(key, 'base64');
  if (saltBytes.length < 8 || keyBytes.length !== KEY_LENGTH) return null;
  return { logN, r, p, salt: saltBytes, key: keyBytes };
}

export function isValidPasswordHash(encoded: string): boolean {
  return parseHash(encoded) !== null;
}

export async function verifyPassword(
  password: string,
  encoded: string,
): Promise<boolean> {
  const parsed = parseHash(encoded);
  if (!parsed) return false;
  const key = await derive(
    password,
    parsed.salt,
    parsed.logN,
    parsed.r,
    parsed.p,
  );
  return timingSafeEqual(key, parsed.key);
}
