/**
 * Re-encrypts every protected column with the active field key. Steps: add a new numbered key to FIELD_KEYS,
 * point ACTIVE_FIELD_KEY at it, run this script, then (optionally) remove the old key from FIELD_KEYS.
 * Rows already using the active key are left alone; the script can be re-run safely.
 */
import { Router } from 'express';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../src/config.ts';
import { activeKeyId, listEncryptedColumns, rotateField } from '../src/db/field-crypto.ts';
import { all, closeDb, openDb, run, withTransaction } from '../src/db/index.ts';
import { runMigrations } from '../src/db/migrate.ts';
import { registerFeatures } from '../src/features/index.ts';

export interface RotationSummary {
  keyId: number;
  columns: { table: string; column: string; rotated: number; unchanged: number }[];
}

export async function rotateAll(): Promise<RotationSummary> {
  openDb();
  runMigrations();
  // Feature modules register their encrypted columns when they mount, so mount them on a throw-away router.
  await registerFeatures(Router());
  const summary: RotationSummary = { keyId: activeKeyId(), columns: [] };
  for (const col of listEncryptedColumns()) {
    const rows = all<Record<string, string | null>>(`SELECT ${col.idColumn} AS id, ${col.column} AS value FROM ${col.table} WHERE ${col.column} IS NOT NULL`);
    let rotated = 0;
    withTransaction(() => {
      for (const row of rows) {
        const id = row['id'];
        const value = row['value'];
        if (id === null || id === undefined || !value) continue;
        const updated = rotateField(value, col.table, col.column, id);
        if (updated === undefined) continue;
        run(`UPDATE ${col.table} SET ${col.column} = ? WHERE ${col.idColumn} = ?`, [updated, id]);
        rotated += 1;
      }
    });
    summary.columns.push({ table: col.table, column: col.column, rotated, unchanged: rows.length - rotated });
  }
  return summary;
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  rotateAll()
    .then((summary) => {
      process.stdout.write(`Active field key: ${summary.keyId} (keys configured: ${[...config.fieldKeys.keys()].join(', ')})\n`);
      for (const c of summary.columns) process.stdout.write(`${c.table}.${c.column}: ${c.rotated} re-encrypted, ${c.unchanged} already current\n`);
      process.stdout.write('Done. Older keys can be removed from FIELD_KEYS once every column reports 0 rows to re-encrypt.\n');
      closeDb();
    })
    .catch((err: Error) => {
      process.stderr.write(`\nKey rotation stopped.\n${err.message}\nNo partial changes were kept.\n\n`);
      closeDb();
      process.exit(1);
    });
}
