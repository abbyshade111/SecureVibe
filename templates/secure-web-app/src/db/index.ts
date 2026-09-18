/**
 * The only door to the database. Every query goes through these helpers with bound parameters — SQL is never
 * built by string concatenation with user input. The database file is created with owner-only permissions.
 */
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { config } from '../config.ts';

export type SqlValue = string | number | bigint | Buffer | null;
export type SqlParam = SqlValue | boolean | undefined | Date;

let db: DatabaseSync | undefined;
let statements = new Map<string, StatementSync>();
let transactionDepth = 0;

export function dbFilePath(): string {
  return resolve(config.dataDir, 'app.sqlite');
}

function applyPragmas(d: DatabaseSync): void {
  d.exec('PRAGMA journal_mode = WAL');
  d.exec('PRAGMA foreign_keys = ON');
  d.exec('PRAGMA busy_timeout = 5000');
  d.exec('PRAGMA secure_delete = ON');
  d.exec('PRAGMA synchronous = NORMAL');
  d.exec('PRAGMA temp_store = MEMORY');
}

/** Opens (or returns) the application database. `file` defaults to DATA_DIR/app.sqlite; ':memory:' is allowed for tests. */
export function openDb(file: string = dbFilePath()): DatabaseSync {
  if (db) return db;
  const onDisk = file !== ':memory:';
  if (onDisk) {
    mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
    chmodSync(config.dataDir, 0o700);
  }
  const isNew = onDisk && !existsSync(file);
  db = new DatabaseSync(file);
  if (isNew) chmodSync(file, 0o600);
  applyPragmas(db);
  if (onDisk) {
    // The WAL and shared-memory files appear once WAL mode is on; keep them owner-only as well.
    for (const suffix of ['-wal', '-shm']) {
      if (existsSync(file + suffix)) chmodSync(file + suffix, 0o600);
    }
  }
  statements = new Map();
  return db;
}

export function getDb(): DatabaseSync {
  if (!db) throw new Error('Database is not open. Call openDb() first.');
  return db;
}

export function closeDb(): void {
  if (!db) return;
  statements.clear();
  db.close();
  db = undefined;
}

function toSqlValue(v: SqlParam): SqlValue {
  if (v === undefined) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (v instanceof Date) return v.toISOString();
  return v;
}

/** Prepares (and caches) a statement. Use run/get/all for the common cases. */
export function q(sql: string): StatementSync {
  const d = getDb();
  let stmt = statements.get(sql);
  if (!stmt) {
    stmt = d.prepare(sql);
    statements.set(sql, stmt);
  }
  return stmt;
}

export function run(sql: string, params: SqlParam[] = []): { changes: number; lastInsertRowid: number } {
  const result = q(sql).run(...params.map(toSqlValue));
  return { changes: Number(result.changes), lastInsertRowid: Number(result.lastInsertRowid) };
}

export function get<T extends object = Record<string, SqlValue>>(sql: string, params: SqlParam[] = []): T | undefined {
  const row = q(sql).get(...params.map(toSqlValue));
  return row === undefined ? undefined : ({ ...row } as T);
}

export function all<T extends object = Record<string, SqlValue>>(sql: string, params: SqlParam[] = []): T[] {
  return q(sql)
    .all(...params.map(toSqlValue))
    .map((row) => ({ ...row }) as T);
}

/** Runs `fn` inside a transaction (BEGIN IMMEDIATE). Nested calls become savepoints. Any throw rolls back. */
export function withTransaction<T>(fn: () => T): T {
  const d = getDb();
  const nested = transactionDepth > 0;
  const savepoint = `sp_${transactionDepth}`;
  if (nested) d.exec(`SAVEPOINT ${savepoint}`);
  else d.exec('BEGIN IMMEDIATE');
  transactionDepth += 1;
  try {
    const result = fn();
    transactionDepth -= 1;
    if (nested) d.exec(`RELEASE SAVEPOINT ${savepoint}`);
    else d.exec('COMMIT');
    return result;
  } catch (err) {
    transactionDepth -= 1;
    if (nested) d.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
    else d.exec('ROLLBACK');
    throw err;
  }
}

/** Writes pending WAL frames into the main file and truncates the log (used after deleting personal data). */
export function checkpoint(): void {
  if (!db) return;
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } catch {
    // Another connection may hold the log open; the next checkpoint will catch up.
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

/** Clamp a page size so list queries always carry a bounded LIMIT. */
export function clampLimit(requested: number | undefined, fallback = 50, max = 200): number {
  if (requested === undefined || !Number.isFinite(requested)) return fallback;
  return Math.max(1, Math.min(max, Math.floor(requested)));
}
