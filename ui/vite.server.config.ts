// The BFF, bundled into one ES module for Node (dependencies stay
// external and are installed in the image).
import { builtinModules } from 'node:module';

import { defineConfig } from 'vite';

import packageJson from './package.json' with { type: 'json' };

const external = [
  ...builtinModules,
  ...builtinModules.map((name) => `node:${name}`),
  ...Object.keys(packageJson.dependencies),
];

export default defineConfig({
  build: {
    ssr: 'server/main.ts',
    outDir: 'dist/server',
    emptyOutDir: true,
    target: 'node24',
    sourcemap: true,
    rollupOptions: {
      external: (id) =>
        external.some((name) => id === name || id.startsWith(`${name}/`)),
      output: { entryFileNames: 'main.js', format: 'es' },
    },
  },
});
