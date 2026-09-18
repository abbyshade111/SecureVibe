/**
 * Creates the database (if needed) and applies pending migrations. Run by `npm run setup`; safe to run any time.
 */
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../src/config.ts';
import { closeDb, dbFilePath, openDb } from '../src/db/index.ts';
import { runMigrations } from '../src/db/migrate.ts';

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    openDb();
    const result = runMigrations();
    process.stdout.write(`Database: ${dbFilePath()} (data folder ${config.dataDir})\n`);
    process.stdout.write(result.applied.length > 0 ? `Applied ${result.applied.length} migration(s): ${result.applied.join(', ')}\n` : 'Database is up to date.\n');
    if (result.changedAfterApply.length > 0) {
      process.stdout.write(`Warning: these migration files changed after they were applied: ${result.changedAfterApply.join(', ')}. Add a new migration instead of editing old ones.\n`);
    }
    closeDb();
  } catch (err) {
    process.stderr.write(`\nThe database could not be prepared.\n${(err as Error).message}\n\n`);
    closeDb();
    process.exit(1);
  }
}
