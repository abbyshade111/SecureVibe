import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Server code imports the shared schemas as "@shared/<name>.js"; the files are TypeScript.
const shared = fileURLToPath(new URL('../shared/src/', import.meta.url));

export default defineConfig({
  resolve: {
    alias: [{ find: /^@shared\/(.*)\.js$/, replacement: `${shared}$1.ts` }],
  },
  test: {
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup-home.ts'],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
