// Passkeys end to end with Chromium's virtual authenticator: add one in
// Settings, sign in with it, remove it, sign out.

import { expect, test } from '@playwright/test';

import { DEV_PASSWORD } from '../../server/dev/users.ts';
import { nextCode, open } from './helpers.ts';

test('add a passkey, sign in with it and remove it', async ({
  page,
  context,
}) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await open(page, '/settings');
  const card = page.getByRole('region', { name: 'Passkeys' });
  await expect(card.getByText('No passkeys yet.')).toBeVisible();
  await card.getByRole('button', { name: 'Add passkey' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add a passkey' });
  await dialog.getByLabel('Name').fill('Test key');
  await dialog.getByLabel('Password').fill(DEV_PASSWORD);
  await dialog.getByLabel('Code').fill(nextCode());
  await dialog.getByRole('button', { name: 'Continue' }).click();
  await expect(dialog).toBeHidden();
  await expect(card.getByText('Test key')).toBeVisible();
  await expect(card.getByText('never used')).toBeVisible();

  // Drop the shared session's cookie (other tests still use it) rather
  // than signing it out.
  await context.clearCookies();
  await page.reload();
  await expect(
    page.getByRole('heading', { name: 'Sign in to the console' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await expect(
    page.getByRole('navigation', { name: 'Main' }).first(),
  ).toBeVisible();

  await open(page, '/settings');
  await expect(card.getByText('used now')).toBeVisible();
  await card.getByRole('button', { name: 'Remove' }).click();
  await page
    .getByRole('dialog', { name: 'Remove passkey' })
    .getByRole('button', { name: 'Remove' })
    .click();
  await expect(card.getByText('No passkeys yet.')).toBeVisible();

  // This session is the passkey's own: signing out ends it.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(
    page.getByRole('heading', { name: 'Sign in to the console' }),
  ).toBeVisible();
});
