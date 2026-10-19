// Two test projects: the SPA in jsdom, the BFF and shared code in Node.
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    restoreMocks: true,
    projects: [
      {
        plugins: [react()],
        test: {
          name: 'web',
          include: ['src/**/*.test.{ts,tsx}'],
          exclude: ['src/**/*.node.test.ts'],
          environment: 'jsdom',
          setupFiles: ['./src/test-setup.ts'],
        },
      },
      {
        test: {
          name: 'node',
          include: [
            '{server,shared,scripts}/**/*.test.ts',
            'src/**/*.node.test.ts',
          ],
          environment: 'node',
        },
      },
    ],
  },
});
