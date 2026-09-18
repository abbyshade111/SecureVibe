/**
 * Writes routes.manifest.json: every page and API route with who may use it, straight from the live route
 * registry. SecureVibe compares this file with the running app so the two can never drift apart.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { APP_ROOT } from '../src/config.ts';
import { createApp } from '../src/app.ts';
import { closeDb, openDb } from '../src/db/index.ts';
import { runMigrations } from '../src/db/migrate.ts';
import { summariseRoutes } from '../src/security/routes.ts';

export async function exportRoutes(): Promise<ReturnType<typeof summariseRoutes>> {
  openDb(':memory:');
  runMigrations();
  await createApp();
  return summariseRoutes();
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  exportRoutes()
    .then((routes) => {
      const file = resolve(APP_ROOT, 'routes.manifest.json');
      writeFileSync(file, `${JSON.stringify(routes, null, 2)}\n`);
      process.stdout.write(`Wrote ${routes.length} routes to ${file}\n`);
      closeDb();
    })
    .catch((err: Error) => {
      process.stderr.write(`\nCould not export the routes.\n${err.message}\n\n`);
      closeDb();
      process.exit(1);
    });
}
