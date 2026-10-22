import { expect, type Page } from '@playwright/test';

import { base32Decode, totpAt } from '../../server/auth/totp.ts';
import { DEV_TOTP_SECRET, E2E_TIME } from '../../server/dev/users.ts';

export const AUTH_FILE = 'test-results/.auth/dev.json';

// The server's clock is frozen at E2E_TIME, so the current code is fixed;
// a code works once per user, which is why tests share one signed-in
// state (setup) and sign in through the form only once.
export function currentCode(): string {
  return totpAt(base32Decode(DEV_TOTP_SECRET), Math.floor(E2E_TIME / 1000));
}

// The code of the next 30-second step: the server accepts one step of
// drift, so a user signed in with currentCode() can confirm once more.
export function nextCode(): string {
  return totpAt(
    base32Decode(DEV_TOTP_SECRET),
    Math.floor(E2E_TIME / 1000) + 30,
  );
}

// Freezes the browser clock at the server's time and opens a screen.
export async function open(page: Page, path: string): Promise<void> {
  await page.clock.setFixedTime(E2E_TIME);
  await page.goto(path);
  await expect(
    page.getByRole('navigation', { name: 'Main' }).first(),
  ).toBeVisible();
}
