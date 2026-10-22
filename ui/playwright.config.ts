// Browser tests: the built SPA served by the development BFF (in-memory
// gateway, synthetic traffic, frozen clock). Screenshots are compared on
// Linux only (CI, or `npm run e2e:docker`), where fonts render the same.

import { defineConfig, devices } from '@playwright/test';

import { E2E_TIME } from './server/dev/users.ts';

const PORT = 9911;
// localhost, not 127.0.0.1: WebAuthn takes no IP address as the RP ID.
const ORIGIN = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 1 : 0,
  reporter: process.env['CI']
    ? [['list'], ['html', { open: 'never' }]]
    : 'list',
  snapshotPathTemplate: '{testDir}/__screenshots__/{arg}{ext}',
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.002, animations: 'disabled' },
  },
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
    timezoneId: 'UTC',
    locale: 'en-US',
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      name: 'desktop',
      dependencies: ['setup'],
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
        storageState: 'test-results/.auth/dev.json',
      },
    },
  ],
  webServer: {
    command: 'node server/dev/dev.ts',
    url: `http://127.0.0.1:${PORT}/api/whoami`,
    reuseExistingServer: false,
    env: {
      LG_PORT: String(PORT),
      LG_ORIGIN: ORIGIN,
      LG_STATIC: 'dist/web',
      LG_FIXED_TIME: String(E2E_TIME),
    },
  },
});
