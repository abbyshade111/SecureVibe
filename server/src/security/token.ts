/**
 * Startup token and sessions (DESIGN §4.3, ADR-005).
 *
 * At startup SecureVibe generates a 32-byte token and prints it once inside the URL it opens:
 *   http://127.0.0.1:<port>/auth/token?t=<token>
 * GET /auth/token exchanges the token (single use per process) for an HttpOnly, SameSite=Strict session cookie.
 * Every session carries its own CSRF token, returned by GET /api/status and required as X-CSRF-Token on mutations.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = 'securevibe_session';
export const CSRF_HEADER = 'x-csrf-token';

export interface SessionRecord {
  id: string;
  csrfToken: string;
  createdAt: number;
  lastSeenAt: number;
}

export interface SessionManagerOptions {
  /** Idle limit for a session in ms (default 12 hours). */
  idleMs?: number;
  /** Provide a token instead of generating one (tests). */
  token?: string;
  now?: () => number;
}

function tokensEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export class SessionManager {
  readonly startupToken: string;
  private tokenUsed = false;
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly idleMs: number;
  private readonly now: () => number;

  constructor(opts: SessionManagerOptions = {}) {
    this.startupToken = opts.token ?? randomBytes(32).toString('base64url');
    this.idleMs = opts.idleMs ?? 12 * 60 * 60 * 1000;
    this.now = opts.now ?? Date.now;
  }

  get tokenAlreadyUsed(): boolean {
    return this.tokenUsed;
  }

  tokenUrl(host: string, port: number): string {
    return `http://${host}:${port}/auth/token?t=${this.startupToken}`;
  }

  /**
   * Exchanges the startup token for a new session. Returns undefined when the token is wrong.
   *
   * The token stays valid for the life of the process rather than for a single request: a browser prefetch, an
   * antivirus scanner or simply reopening the printed link would otherwise burn it and leave the person with no
   * way in but a restart. The token is a local, per-process secret printed only to the owner's own terminal, and
   * every request still has to pass the Host, Origin and CSRF checks, so accepting it more than once does not
   * widen who can reach SecureVibe.
   */
  exchange(token: string | undefined): SessionRecord | undefined {
    if (!token || !tokensEqual(token, this.startupToken)) return undefined;
    this.tokenUsed = true;
    return this.createSession();
  }

  /** Creates a session directly (used by the DAST self-assessment bootstrap and tests). */
  createSession(): SessionRecord {
    const record: SessionRecord = {
      id: randomBytes(32).toString('base64url'),
      csrfToken: randomBytes(32).toString('base64url'),
      createdAt: this.now(),
      lastSeenAt: this.now(),
    };
    this.sessions.set(record.id, record);
    return record;
  }

  /** Looks a session up by cookie value and refreshes its idle timer. */
  validate(sessionId: string | undefined): SessionRecord | undefined {
    if (!sessionId) return undefined;
    const record = this.sessions.get(sessionId);
    if (!record) return undefined;
    if (this.now() - record.lastSeenAt > this.idleMs) {
      this.sessions.delete(sessionId);
      return undefined;
    }
    record.lastSeenAt = this.now();
    return record;
  }

  csrfMatches(session: SessionRecord, presented: string | undefined): boolean {
    return !!presented && tokensEqual(presented, session.csrfToken);
  }

  revoke(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  get sessionCount(): number {
    return this.sessions.size;
  }
}

/** Parses a Cookie header into a map (no decoding beyond percent-decoding of values). */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

export function sessionCookieHeader(sessionId: string): string {
  // No `Secure`: the tool only ever speaks plain HTTP on the loopback interface.
  return `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; SameSite=Strict`;
}

export function clearSessionCookieHeader(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}
