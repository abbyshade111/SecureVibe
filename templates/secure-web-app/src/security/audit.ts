/**
 * Append-only, hash-chained audit table. Each row stores the hash of the previous row and
 * hash = sha256(prev_hash + canonical JSON of the row). `verifyChain()` recomputes every hash so that a deleted,
 * edited or inserted row is detected. Retention pruning removes the oldest rows only, so the remaining chain stays valid.
 */
import { createHash } from 'node:crypto';
import { all, get, nowIso, run, withTransaction } from '../db/index.ts';

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditRecord {
  ts: string;
  event: string;
  reqId: string | null;
  userId: string | null;
  ip: string | null;
  route: string | null;
  outcome: 'success' | 'failure' | 'blocked';
  fields: Record<string, unknown>;
}

interface AuditRow {
  seq: number;
  ts: string;
  event: string;
  req_id: string | null;
  user_id: string | null;
  ip: string | null;
  route: string | null;
  outcome: string;
  fields: string;
  prev_hash: string;
  hash: string;
}

/** Deterministic JSON: keys sorted at every level so the same data always hashes the same. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(',')}}`;
}

function rowHash(prevHash: string, row: Omit<AuditRow, 'seq' | 'prev_hash' | 'hash'>): string {
  const canonical = canonicalJson({
    ts: row.ts,
    event: row.event,
    req_id: row.req_id,
    user_id: row.user_id,
    ip: row.ip,
    route: row.route,
    outcome: row.outcome,
    fields: row.fields,
  });
  return createHash('sha256').update(prevHash + canonical).digest('hex');
}

export function appendAudit(record: AuditRecord): number {
  return withTransaction(() => {
    const last = get<{ hash: string }>('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1');
    const prevHash = last?.hash ?? GENESIS_HASH;
    const row = {
      ts: record.ts,
      event: record.event,
      req_id: record.reqId,
      user_id: record.userId,
      ip: record.ip,
      route: record.route,
      outcome: record.outcome,
      fields: canonicalJson(record.fields),
    };
    const hash = rowHash(prevHash, row);
    const result = run(
      'INSERT INTO audit_log (ts, event, req_id, user_id, ip, route, outcome, fields, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [row.ts, row.event, row.req_id, row.user_id, row.ip, row.route, row.outcome, row.fields, prevHash, hash],
    );
    return result.lastInsertRowid;
  });
}

export interface ChainVerification {
  ok: boolean;
  checkedRows: number;
  brokenAtSeq?: number;
  reason?: string;
}

export function verifyChain(): ChainVerification {
  const rows = all<AuditRow>('SELECT * FROM audit_log ORDER BY seq ASC');
  let prevHash: string | undefined;
  let checked = 0;
  for (const row of rows) {
    if (prevHash !== undefined && row.prev_hash !== prevHash) {
      return { ok: false, checkedRows: checked, brokenAtSeq: row.seq, reason: 'The link to the previous row does not match (a row was removed or edited).' };
    }
    const expected = rowHash(row.prev_hash, row);
    if (expected !== row.hash) {
      return { ok: false, checkedRows: checked, brokenAtSeq: row.seq, reason: 'The row content does not match its hash (the row was edited).' };
    }
    prevHash = row.hash;
    checked += 1;
  }
  return { ok: true, checkedRows: checked };
}

export interface AuditQuery {
  since?: string;
  event?: string;
  userId?: string;
  limit: number;
  offset?: number;
}

export function queryAudit(qry: AuditQuery): AuditRecord[] {
  const where: string[] = [];
  const params: (string | number)[] = [];
  if (qry.since) {
    where.push('ts >= ?');
    params.push(qry.since);
  }
  if (qry.event) {
    where.push('event = ?');
    params.push(qry.event);
  }
  if (qry.userId) {
    where.push('user_id = ?');
    params.push(qry.userId);
  }
  const sql = `SELECT * FROM audit_log ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT ? OFFSET ?`;
  params.push(qry.limit, qry.offset ?? 0);
  return all<AuditRow>(sql, params).map((r) => ({
    ts: r.ts,
    event: r.event,
    reqId: r.req_id,
    userId: r.user_id,
    ip: r.ip,
    route: r.route,
    outcome: r.outcome as AuditRecord['outcome'],
    fields: JSON.parse(r.fields) as Record<string, unknown>,
  }));
}

export function countAudit(): number {
  return get<{ n: number }>('SELECT COUNT(*) AS n FROM audit_log')?.n ?? 0;
}

/** Deletes rows older than the retention window (oldest first, so the chain among remaining rows stays intact). */
export function pruneAudit(retentionDays: number): number {
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  return run('DELETE FROM audit_log WHERE ts < ?', [cutoff]).changes;
}

export function auditNow(): string {
  return nowIso();
}
