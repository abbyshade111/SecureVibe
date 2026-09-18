/**
 * Server-side sessions. The browser only holds a random 256-bit id in an HttpOnly, SameSite=Strict cookie
 * (`sid`, or `__Host-sid` with the Secure flag in TLS modes). The database stores HMAC-SHA256(SESSION_SECRET, id),
 * so a copy of the database cannot be used to hijack sessions. Sessions expire after an idle period and after an
 * absolute lifetime, are regenerated on sign-in and after a one-time code, and are capped per user.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { config } from '../config.ts';
import { all, get, nowIso, run, withTransaction } from '../db/index.ts';
import { findUserById, toSessionUser } from '../features/auth/repo.ts';
import { emit } from './events.ts';

export const SESSION_COOKIE = config.tlsEnabled ? '__Host-sid' : 'sid';
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const TOUCH_INTERVAL_MS = 60_000;

export interface SessionRow {
  id_hash: string;
  user_id: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip: string | null;
  ua_hash: string | null;
  mfa_verified: number;
  reauth_at: string | null;
  revoked_at: string | null;
  data: string;
}

export interface FlashMessage {
  type: 'success' | 'error' | 'info';
  message: string;
}

export function hashSessionId(id: string): string {
  return createHmac('sha256', Buffer.from(config.SESSION_SECRET, 'base64')).update(id).digest('hex');
}

function hashUserAgent(ua: string | undefined): string | null {
  return ua ? createHash('sha256').update(ua).digest('hex').slice(0, 16) : null;
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name && out[name] === undefined) out[name] = value;
  }
  return out;
}

export function sessionCookieAttributes(): string {
  const attrs = ['Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (config.tlsEnabled) attrs.push('Secure');
  return attrs.join('; ');
}

function setSessionCookie(res: Response, id: string): void {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${id}; ${sessionCookieAttributes()}`);
}

export function clearSessionCookie(res: Response): void {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; ${sessionCookieAttributes()}; Max-Age=0`);
}

function expiryFor(createdAt: string, lastSeenAt: string): string {
  const idle = new Date(lastSeenAt).getTime() + config.sessionIdleMinutes * 60_000;
  const absolute = new Date(createdAt).getTime() + config.sessionAbsoluteHours * 3_600_000;
  return new Date(Math.min(idle, absolute)).toISOString();
}

function loadRow(idHash: string): SessionRow | undefined {
  return get<SessionRow>('SELECT * FROM sessions WHERE id_hash = ?', [idHash]);
}

/**
 * Oldest creation time a session may have and still be usable. The absolute lifetime is re-checked from
 * `created_at` on every request, so a stored `expires_at` (which only carries the rolling idle timeout once the
 * session has been touched) can never keep a session alive beyond it.
 */
function absoluteCutoffIso(now: number = Date.now()): string {
  return new Date(now - config.sessionAbsoluteHours * 3_600_000).toISOString();
}

function isLive(row: SessionRow, now: string): boolean {
  return row.revoked_at === null && row.expires_at > now && row.created_at > absoluteCutoffIso();
}

/**
 * The per-request session object. It may not be persisted yet (`exists` false): the first `set()` or `ensure()`
 * creates the database row and the cookie. Data is written through immediately.
 */
export class SessionHandle {
  idHash: string | undefined;
  userId: string | null;
  mfaVerified: boolean;
  reauthAt: string | null;
  createdAt: string | null;
  private data: Record<string, unknown>;
  private readonly req: Request;
  private readonly res: Response;

  constructor(req: Request, res: Response, row?: SessionRow) {
    this.req = req;
    this.res = res;
    this.idHash = row?.id_hash;
    this.userId = row?.user_id ?? null;
    this.mfaVerified = row ? row.mfa_verified === 1 : false;
    this.reauthAt = row?.reauth_at ?? null;
    this.createdAt = row?.created_at ?? null;
    this.data = row ? (JSON.parse(row.data) as Record<string, unknown>) : {};
  }

  get exists(): boolean {
    return this.idHash !== undefined;
  }

  /** First 8 characters of the id hash — the only form in which a session id appears in logs. */
  get logId(): string | null {
    return this.idHash ? this.idHash.slice(0, 8) : null;
  }

  /** Creates the session row and cookie when there is none yet. */
  ensure(): void {
    if (this.idHash) return;
    const id = randomBytes(32).toString('base64url');
    const idHash = hashSessionId(id);
    const now = nowIso();
    run(
      'INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, ip, ua_hash, mfa_verified, data) VALUES (?, NULL, ?, ?, ?, ?, ?, 0, ?)',
      [idHash, now, now, expiryFor(now, now), this.req.ip ?? null, hashUserAgent(this.req.get('user-agent')), JSON.stringify(this.data)],
    );
    this.idHash = idHash;
    this.createdAt = now;
    setSessionCookie(this.res, id);
  }

  get<T = unknown>(key: string): T | undefined {
    return this.data[key] as T | undefined;
  }

  set(key: string, value: unknown): void {
    this.ensure();
    if (value === undefined) delete this.data[key];
    else this.data[key] = value;
    this.persistData();
  }

  delete(key: string): void {
    if (!(key in this.data)) return;
    delete this.data[key];
    this.persistData();
  }

  flash(type: FlashMessage['type'], message: string): void {
    const list = (this.get<FlashMessage[]>('flash') ?? []).slice(-4);
    list.push({ type, message });
    this.set('flash', list);
  }

  takeFlash(): FlashMessage[] {
    const list = this.get<FlashMessage[]>('flash') ?? [];
    if (list.length) this.delete('flash');
    return list;
  }

  /** Whether the user confirmed their password recently enough for a sensitive change. */
  recentlyReauthenticated(withinMinutes = 5): boolean {
    if (!this.reauthAt) return false;
    return Date.now() - new Date(this.reauthAt).getTime() <= withinMinutes * 60_000;
  }

  markReauthenticated(): void {
    if (!this.idHash) return;
    this.reauthAt = nowIso();
    run('UPDATE sessions SET reauth_at = ? WHERE id_hash = ?', [this.reauthAt, this.idHash]);
  }

  private persistData(): void {
    if (!this.idHash) return;
    run('UPDATE sessions SET data = ? WHERE id_hash = ?', [JSON.stringify(this.data), this.idHash]);
  }

  /**
   * Replaces the session id (the old one becomes invalid) and binds it to a user. Called on sign-in and again
   * when the one-time code is verified, so an id issued before authentication is never valid afterwards.
   */
  rotate(userId: string, mfaVerified: boolean, keepData: string[] = []): void {
    const kept: Record<string, unknown> = {};
    for (const key of keepData) if (key in this.data) kept[key] = this.data[key];
    const oldHash = this.idHash;
    const id = randomBytes(32).toString('base64url');
    const idHash = hashSessionId(id);
    const now = nowIso();
    withTransaction(() => {
      if (oldHash) run('DELETE FROM sessions WHERE id_hash = ?', [oldHash]);
      run(
        'INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, ip, ua_hash, mfa_verified, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [idHash, userId, now, now, expiryFor(now, now), this.req.ip ?? null, hashUserAgent(this.req.get('user-agent')), mfaVerified ? 1 : 0, JSON.stringify(kept)],
      );
      if (mfaVerified) enforceConcurrentLimit(userId, idHash);
    });
    this.idHash = idHash;
    this.userId = userId;
    this.mfaVerified = mfaVerified;
    this.reauthAt = null;
    this.createdAt = now;
    this.data = kept;
    setSessionCookie(this.res, id);
  }

  /** Ends this session on the server and clears the cookie. */
  destroy(): void {
    if (this.idHash) run('UPDATE sessions SET revoked_at = ?, data = ? WHERE id_hash = ?', [nowIso(), '{}', this.idHash]);
    this.idHash = undefined;
    this.userId = null;
    this.mfaVerified = false;
    this.data = {};
    clearSessionCookie(this.res);
  }
}

function enforceConcurrentLimit(userId: string, currentIdHash: string): void {
  const now = nowIso();
  const live = all<{ id_hash: string }>(
    'SELECT id_hash FROM sessions WHERE user_id = ? AND mfa_verified = 1 AND revoked_at IS NULL AND expires_at > ? AND created_at > ? ORDER BY created_at DESC',
    [userId, now, absoluteCutoffIso()],
  );
  const excess = live.slice(config.sessionMaxConcurrent).filter((s) => s.id_hash !== currentIdHash);
  for (const s of excess) run('UPDATE sessions SET revoked_at = ? WHERE id_hash = ?', [now, s.id_hash]);
}

export function sessionMiddleware(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    let row: SessionRow | undefined;
    if (raw && SESSION_ID_PATTERN.test(raw)) {
      const idHash = hashSessionId(raw);
      const found = loadRow(idHash);
      const now = nowIso();
      if (found && isLive(found, now)) {
        row = found;
        if (Date.now() - new Date(found.last_seen_at).getTime() > TOUCH_INTERVAL_MS) {
          const expires = expiryFor(found.created_at, now);
          run('UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id_hash = ?', [now, expires, idHash]);
        }
      } else if (found) {
        clearSessionCookie(res);
      }
    }
    req.session = new SessionHandle(req, res, row);
    req.user = undefined;
    if (row?.user_id && row.mfa_verified === 1) {
      const user = findUserById(row.user_id);
      if (user && user.status === 'active') {
        req.user = toSessionUser(user);
      } else {
        req.session.destroy();
        req.session = new SessionHandle(req, res);
      }
    }
    next();
  };
}

export interface SessionSummary {
  idPrefix: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip: string | null;
  current: boolean;
}

export function listUserSessions(userId: string, currentIdHash: string | undefined): SessionSummary[] {
  const now = nowIso();
  return all<SessionRow>(
    'SELECT * FROM sessions WHERE user_id = ? AND mfa_verified = 1 AND revoked_at IS NULL AND expires_at > ? AND created_at > ? ORDER BY created_at DESC LIMIT 50',
    [userId, now, absoluteCutoffIso()],
  ).map((s) => ({
    idPrefix: s.id_hash.slice(0, 12),
    createdAt: s.created_at,
    lastSeenAt: s.last_seen_at,
    expiresAt: s.expires_at,
    ip: s.ip,
    current: s.id_hash === currentIdHash,
  }));
}

export function revokeUserSession(userId: string, idPrefix: string): boolean {
  const rows = all<{ id_hash: string }>('SELECT id_hash FROM sessions WHERE user_id = ? AND revoked_at IS NULL', [userId]);
  const target = rows.find((r) => r.id_hash.length >= idPrefix.length && timingSafeEqual(Buffer.from(r.id_hash.slice(0, idPrefix.length)), Buffer.from(idPrefix)));
  if (!target) return false;
  run('UPDATE sessions SET revoked_at = ? WHERE id_hash = ?', [nowIso(), target.id_hash]);
  return true;
}

/** Ends every session of a user (optionally keeping the current one). Emits `session.revoked`. */
export function revokeAllForUser(userId: string, options: { exceptIdHash?: string; reason: string; req?: Request }): number {
  const now = nowIso();
  const result = options.exceptIdHash
    ? run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id_hash <> ?', [now, userId, options.exceptIdHash])
    : run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL', [now, userId]);
  emit('session.revoked', { req: options.req, userId, count: result.changes, reason: options.reason });
  return result.changes;
}

/** Removes expired and long-revoked rows. Called periodically by server.ts. */
export function cleanupSessions(): number {
  const now = nowIso();
  const dayAgo = new Date(Date.now() - 86_400_000).toISOString();
  return run('DELETE FROM sessions WHERE expires_at < ? OR created_at <= ? OR (revoked_at IS NOT NULL AND revoked_at < ?)', [now, absoluteCutoffIso(), dayAgo]).changes;
}
