// Contract tests against a real gateway and ClickHouse (npm run contract).
// Not part of `npm test`: they start processes and a container.
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

export default defineConfig({
  root: fileURLToPath(new URL('../..', import.meta.url)),
  test: {
    name: 'contract',
    include: ['server/contract/**/*.contract.ts'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 180_000,
  },
});
