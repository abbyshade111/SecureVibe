// Fixture: the database driver used directly, outside src/db (CONTRACTS §3).
import { DatabaseSync } from 'node:sqlite';

export function directQuery(): unknown {
  const store = new DatabaseSync(':memory:');
  return store.prepare('SELECT 1').all();
}
