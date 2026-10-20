import { expect, test as setup } from '@playwright/test';

import { DEV_PASSWORD } from '../../server/dev/users.ts';
import { AUTH_FILE, currentCode } from './helpers.ts';

setup('sign in as the operator', async ({ page }) => {
  await page.goto('/');
  const status = await page.evaluate(
    async ([password, totp]) => {
      const response = await fetch('/api/session', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'dev', password, totp }),
      });
      return response.status;
    },
    [DEV_PASSWORD, currentCode()] as const,
  );
  expect(status).toBe(200);
  await page.context().storageState({ path: AUTH_FILE });
});
