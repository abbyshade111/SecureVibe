/**
 * The web tests: pure functions from the pages (text wording, ordering), run with the same @shared alias the
 * build uses. `web/src/pages/plainActivity.test.ts` existed for days with nothing running it, so it guarded
 * nothing; `npm test` at the root now runs this after the server suite, and the checks workflow runs it too.
 */
import { mergeConfig } from 'vite';
import { defineConfig } from 'vitest/config';
import viteConfig from './vite.config';

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
      environment: 'node',
    },
  }),
);
