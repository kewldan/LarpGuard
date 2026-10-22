// Screenshots of the screens the design specifies at both widths and in
// both themes. Linux only: font rasterization differs per platform.

import { expect, test } from '@playwright/test';

import { open } from './helpers.ts';

test.skip(process.platform !== 'linux', 'screenshots are compared on Linux');

for (const theme of ['dark', 'light'] as const) {
  test.describe(`${theme} theme`, () => {
    test.use({ colorScheme: theme });

    for (const [name, size] of [
      ['desktop', { width: 1440, height: 900 }],
      ['phone', { width: 390, height: 844 }],
    ] as const) {
      test(`overview, ${name}`, async ({ page }) => {
        await page.setViewportSize(size);
        await open(page, '/');
        await expect(page.getByText('Verdicts over time')).toBeVisible();
        await expect(page).toHaveScreenshot(`overview-${name}-${theme}.png`, {
          fullPage: name === 'desktop',
        });
      });

      test(`configuration, ${name}`, async ({ page }) => {
        await page.setViewportSize(size);
        await open(page, '/config?section=captcha');
        await expect(
          page.getByRole('heading', { name: 'CAPTCHA', exact: true }),
        ).toBeVisible();
        await expect(page).toHaveScreenshot(
          `configuration-${name}-${theme}.png`,
          { fullPage: name === 'desktop' },
        );
      });

      test(`attack mode, ${name}`, async ({ page }) => {
        await page.setViewportSize(size);
        await open(page, '/attack');
        await expect(page.getByText('What attack mode does')).toBeVisible();
        await expect(page).toHaveScreenshot(`attack-${name}-${theme}.png`, {
          fullPage: name === 'desktop',
        });
      });
    }
  });
}
