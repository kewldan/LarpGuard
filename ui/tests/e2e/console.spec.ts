// The console end to end: the built SPA against the development BFF.

import { expect, test } from '@playwright/test';

import { DEV_PASSWORD } from '../../server/dev/users.ts';
import { currentCode, open } from './helpers.ts';

test.describe('sign-in', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('password and code, then a viewer sees no change controls', async ({
    page,
  }) => {
    await page.goto('/lists');
    await expect(
      page.getByRole('heading', { name: 'Sign in to the console' }),
    ).toBeVisible();
    await page.getByLabel('Username').fill('viewer');
    await page.getByLabel('Password').fill(DEV_PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    // The sixth digit signs in by itself.
    await page.getByLabel('Code').fill(currentCode());
    // Lands where the link pointed.
    await expect(
      page.getByRole('heading', { name: 'Lists', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText('Only operators can change this'),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: /Add to/ })).toHaveCount(0);
  });

  test('a wrong code is refused', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel('Username').fill('dev');
    await page.getByLabel('Password').fill(DEV_PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Code').fill('000000');
    await expect(page.getByRole('alert')).toContainText('wrong');
  });
});

test('every screen renders without errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  const screens: [string, string][] = [
    ['/', 'Overview'],
    ['/requests', 'Requests'],
    ['/fingerprints', 'Fingerprints'],
    ['/rules', 'Rules'],
    ['/lists', 'Lists'],
    ['/limits', 'Rate limits'],
    ['/hosts', 'Hosts & policy'],
    ['/crawlers', 'Crawlers'],
    ['/attack', 'What attack mode does'],
    ['/log', 'Decision log'],
    ['/config', 'Configuration'],
    ['/settings', 'Settings'],
  ];
  for (const [path, heading] of screens) {
    await open(page, path);
    await expect(
      page.getByRole('heading', { name: heading, exact: true }).first(),
    ).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('block a network from a request, then revert it in the log', async ({
  page,
}) => {
  await open(page, '/requests?action=block');
  await page.getByRole('row').nth(1).click();
  const block = page.getByRole('button', { name: /^Block .*\/(24|48)$/ });
  const label = (await block.textContent()) ?? '';
  const network = label.replace('Block ', '');
  await block.click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Blocked' }),
  ).toBeVisible();

  await open(page, '/lists');
  await expect(page.getByTitle(network, { exact: true })).toBeVisible();

  await open(page, '/log?kind=list');
  await page
    .getByRole('button', { name: /Blocked ip/ })
    .first()
    .click();
  await page.getByRole('button', { name: 'Revert this change' }).click();
  await open(page, '/lists');
  await expect(page.getByText('The block list is empty.')).toBeVisible();
});

test('a rule is type-checked as you type and tested on the last hour', async ({
  page,
}) => {
  await open(page, '/rules?rule=hard_block');
  const editor = page.getByLabel('Expression');
  await editor.fill('score >= 85 and hosst == "a"');
  await expect(page.getByRole('alert')).toContainText(
    "L1:17unknown name 'hosst'",
  );
  await editor.fill('score >= 85 and asn_hosting');
  await expect(
    page.getByText(/Type-checks · bool expression · 2 fields referenced/),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Test against 1h' }).click();
  await expect(page.getByText('Would match')).toBeVisible();
  await expect(page.getByRole('table')).toContainText('block');
  await page.getByRole('button', { name: 'Discard draft' }).click();
});

test('switch a host to enforce and back', async ({ page }) => {
  await open(page, '/hosts?host=shop.example.com');
  await page.getByRole('radio', { name: /ENFORCE/ }).click();
  await page.getByRole('button', { name: 'Switch to enforce' }).click();
  await expect(page.getByText('source: console override')).toBeVisible();
  await page.getByRole('button', { name: 'Revert to source' }).click();
  await expect(
    page.getByText('source: policy.hosts in the config'),
  ).toBeVisible();
});

test('attack mode on for 15 minutes and off', async ({ page }) => {
  await open(page, '/attack');
  await page.getByRole('button', { name: '15m' }).click();
  await page
    .getByRole('button', { name: 'Enable attack mode for 15m' })
    .click();
  await expect(
    page.getByRole('heading', { name: /Attack mode on/ }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: /Attack mode on/ }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Disable now' }).click();
  await expect(
    page.getByRole('heading', { name: /Auto · armed/ }),
  ).toBeVisible();
});

test('the command palette jumps to a host', async ({ page }) => {
  await open(page, '/');
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByRole('combobox', { name: 'Search' }).fill('api.example');
  await expect(
    page.getByRole('option', { name: /api\.example\.com/ }),
  ).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/requests\?host=api\.example\.com/);
});

test('a setting is checked as you type, applied and reverted in the log', async ({
  page,
}) => {
  await open(page, '/config?section=captcha');
  const rounds = page.getByLabel('captcha.rounds');
  await rounds.fill('9');
  await expect(
    page.getByRole('alert').filter({ hasText: 'expected 1..5' }),
  ).toBeVisible();
  await rounds.fill('3');
  await expect(page.getByText('the gateway accepts them')).toBeVisible();
  await page.getByRole('button', { name: 'Review' }).click();
  const review = page.getByRole('dialog', { name: 'Review settings changes' });
  await expect(review).toContainText('captcha.rounds');
  await expect(review).toContainText('after a restart');
  await review.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(
    page.getByText('1 saved setting waits for a restart'),
  ).toBeVisible();

  // Secrets show whether they are set, never their value.
  await open(page, '/config?section=events');
  await expect(page.getByText('set', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('dev-token')).toHaveCount(0);

  await open(page, '/log?kind=settings');
  await page
    .getByRole('button', { name: /captcha\.rounds 2 → 3/ })
    .first()
    .click();
  await page.getByRole('button', { name: 'Revert this change' }).click();
  await open(page, '/config?section=captcha');
  await expect(page.getByText(/waits? for a restart/)).toHaveCount(0);
});

test('the command palette jumps to a setting', async ({ page }) => {
  await open(page, '/');
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByRole('combobox', { name: 'Search' }).fill('round_timeout');
  await expect(
    page.getByRole('option', { name: /captcha\.round_timeout/ }),
  ).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(
    /\/config\?section=captcha&key=captcha\.round_timeout/,
  );
  await expect(page.getByLabel('captcha.round_timeout')).toBeVisible();
});
