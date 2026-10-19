// TOTP (RFC 6238) with HMAC-SHA1, 30-second steps and 6 digits: what
// authenticator apps expect from an otpauth:// URI with defaults.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_STEP_SECONDS = 30;
const DIGITS = 6;

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET.charAt((value << (5 - bits)) & 31);
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error('invalid base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// The code for one time step (RFC 4226 HOTP over the step counter).
export function hotp(secret: Buffer, counter: number, digits = DIGITS): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(message).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totpAt(secret: Buffer, unixSeconds: number, digits = DIGITS) {
  return hotp(secret, Math.floor(unixSeconds / TOTP_STEP_SECONDS), digits);
}

// Accepts the current step and one on either side (clock drift). Returns
// the matched step so a caller can refuse to accept it twice.
export function verifyTotp(
  secretBase32: string,
  code: string,
  unixSeconds: number,
): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const secret = base32Decode(secretBase32);
  const step = Math.floor(unixSeconds / TOTP_STEP_SECONDS);
  const given = Buffer.from(code);
  let matched: number | null = null;
  for (const candidate of [step - 1, step, step + 1]) {
    const expected = Buffer.from(hotp(secret, candidate));
    // Check every candidate: the time taken does not depend on which one.
    if (timingSafeEqual(expected, given)) matched = candidate;
  }
  return matched;
}

export function newTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function otpauthUri(secret: string, user: string): string {
  const label = encodeURIComponent(`LarpGuard:${user}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=LarpGuard`;
}
