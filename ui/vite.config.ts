// The SPA. In development the BFF runs separately (npm run dev) and Vite
// proxies /api to it.
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist/web',
    emptyOutDir: true,
    sourcemap: true,
    // No inline assets: the CSP allows 'self' only.
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:9901',
    },
  },
});
