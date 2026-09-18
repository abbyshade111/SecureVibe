import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const shared = fileURLToPath(new URL('../shared/src/', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [{ find: /^@shared\/(.*)\.js$/, replacement: `${shared}$1.ts` }],
  },
  // The server replaces this marker with the request's CSP nonce when it serves index.html.
  html: { cspNonce: '__CSP_NONCE__' },
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:4173',
      '/auth': 'http://127.0.0.1:4173',
    },
  },
});
