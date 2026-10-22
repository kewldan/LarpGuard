// What every sign-in and re-authentication shares: the failure limiter
// (per user name and per client network) and the password + TOTP check
// with its replay guard.

import type { ConsoleUser } from '../config.ts';
import { FailureLimiter } from './limiter.ts';
import { verifyTotp } from './totp.ts';

// A password check that costs the same for unknown users.
const DUMMY_HASH =
  'scrypt$17$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

export type CheckResult = 'ok' | 'wrong' | 'replay';

export class SignInGuard {
  // Five failures in five minutes lock a name or a client network for five
  // minutes.
  private readonly limiter = new FailureLimiter({
    limit: 5,
    windowMs: 5 * 60_000,
    lockMs: 5 * 60_000,
  });
  // A TOTP code works once.
  private readonly usedSteps = new Map<string, number>();
  private readonly verifyPassword: (
    password: string,
    hash: string,
  ) => Promise<boolean>;

  constructor(
    verifyPassword: (password: string, hash: string) => Promise<boolean>,
  ) {
    this.verifyPassword = verifyPassword;
  }

  // Milliseconds until the first of `keys` unlocks; 0 when none is locked.
  lockedFor(keys: string[], now: number): number {
    return Math.max(0, ...keys.map((key) => this.limiter.lockedFor(key, now)));
  }

  // Records a failure for every key; true when that locked one of them.
  fail(keys: string[], now: number): boolean {
    return keys.map((key) => this.limiter.fail(key, now)).some(Boolean);
  }

  succeed(keys: string[]): void {
    for (const key of keys) this.limiter.succeed(key);
  }

  // Password and code of `user` (undefined: an unknown name, checked
  // against a dummy hash all the same). A matched code is spent.
  async check(
    user: ConsoleUser | undefined,
    password: string,
    totp: string,
    now: number,
  ): Promise<CheckResult> {
    const passwordOk = await this.verifyPassword(
      password,
      user?.password ?? DUMMY_HASH,
    );
    const step = user
      ? verifyTotp(user.totp_secret, totp, Math.floor(now / 1000))
      : null;
    if (!user || !passwordOk || step === null) return 'wrong';
    if ((this.usedSteps.get(user.name) ?? -1) >= step) return 'replay';
    this.usedSteps.set(user.name, step);
    return 'ok';
  }
}
