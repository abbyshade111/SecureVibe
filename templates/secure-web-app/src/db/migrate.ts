/**
 * Migrations runner. SQL files in src/db/migrations are applied once, in file-name order, each inside a
 * transaction, and recorded in `_migrations` with a checksum so a changed file is noticed.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { all, getDb, nowIso, run, withTransaction } from './index.ts';

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'migrations');

interface AppliedRow {
  name: string;
  checksum: string;
}

export interface MigrationResult {
  applied: string[];
  skipped: string[];
  changedAfterApply: string[];
}

export function listMigrationFiles(dir: string = MIGRATIONS_DIR): string[] {
  return readdirSync(dir)
    .filter((f) => /^\d{3}_[a-z0-9_-]+\.sql$/i.test(f))
    .sort();
}

export function runMigrations(dir: string = MIGRATIONS_DIR): MigrationResult {
  const db = getDb();
  db.exec(
    'CREATE TABLE IF NOT EXISTS _migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)',
  );
  const applied = new Map(all<AppliedRow>('SELECT name, checksum FROM _migrations').map((r) => [r.name, r.checksum]));
  const result: MigrationResult = { applied: [], skipped: [], changedAfterApply: [] };

  for (const file of listMigrationFiles(dir)) {
    const sql = readFileSync(join(dir, file), 'utf8');
    const checksum = createHash('sha256').update(sql).digest('hex');
    const existing = applied.get(file);
    if (existing !== undefined) {
      if (existing !== checksum) result.changedAfterApply.push(file);
      result.skipped.push(file);
      continue;
    }
    withTransaction(() => {
      db.exec(sql);
      run('INSERT INTO _migrations (name, checksum, applied_at) VALUES (?, ?, ?)', [file, checksum, nowIso()]);
    });
    result.applied.push(file);
  }
  return result;
}
