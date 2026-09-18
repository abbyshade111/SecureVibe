/**
 * Request checks for the local tool (DESIGN §4.3):
 *  - Host allow-list: 127.0.0.1, localhost, [::1] (with the server port when known) — defeats DNS rebinding.
 *  - Origin / Sec-Fetch-Site on state-changing requests — defeats cross-site requests from other pages.
 *  - Session cookie required for everything under /api and for the SPA pages.
 *  - CSRF token (per session) required as X-CSRF-Token on JSON mutations.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { HttpError, withEvent } from './errors.js';
import { CSRF_HEADER, SESSION_COOKIE, parseCookies, type SessionManager, type SessionRecord } from './token.js';

export const ALLOWED_HOSTNAMES = ['127.0.0.1', 'localhost', '[::1]'] as const;
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface HostCheckOptions {
  /** When set, the Host header must carry exactly this port. Tests leave it unset (ephemeral ports). */
  port?: number;
}

export function splitHost(host: string): { hostname: string; port?: number } | undefined {
  const trimmed = host.trim().toLowerCase();
  if (!trimmed) return undefined;
  const m = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::(\d{1,5}))?$/.exec(trimmed);
  if (!m) return undefined;
  const result: { hostname: string; port?: number } = { hostname: m[1] as string };
  if (m[2] !== undefined) result.port = Number(m[2]);
  return result;
}

export function isAllowedHost(host: string | undefined, opts: HostCheckOptions = {}): boolean {
  if (!host) return false;
  const parsed = splitHost(host);
  if (!parsed) return false;
  if (!(ALLOWED_HOSTNAMES as readonly string[]).includes(parsed.hostname)) return false;
  if (opts.port !== undefined && parsed.port !== undefined && parsed.port !== opts.port) return false;
  return true;
}

export function hostAllowList(opts: HostCheckOptions = {}): RequestHandler {
  return (req, res, next) => {
    if (isAllowedHost(req.headers.host, opts)) {
      next();
      return;
    }
    res.status(421).type('text/plain').send('SecureVibe only answers requests addressed to 127.0.0.1 or localhost.');
  };
}

export function isAllowedOrigin(origin: string, opts: HostCheckOptions = {}): boolean {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:') return false;
  return isAllowedHost(url.host, opts);
}

/**
 * On state-changing requests an Origin header, when present, must be one of ours, and Sec-Fetch-Site, when present,
 * must be same-origin (or none, i.e. typed by the user). Non-browser clients send neither and are still protected by
 * the session cookie plus the CSRF token.
 */
export function originCheck(opts: HostCheckOptions = {}): RequestHandler {
  return (req, _res, next) => {
    if (!MUTATING.has(req.method)) {
      next();
      return;
    }
    const origin = req.header('origin');
    if (origin !== undefined && origin !== 'null' && !isAllowedOrigin(origin, opts)) {
      next(withEvent(new HttpError('forbidden', 'This request came from another website and was blocked.'), 'origin.blocked'));
      return;
    }
    if (origin === 'null') {
      next(withEvent(new HttpError('forbidden', 'This request came from an opaque origin and was blocked.'), 'origin.blocked'));
      return;
    }
    const fetchSite = req.header('sec-fetch-site');
    if (fetchSite !== undefined && fetchSite !== 'same-origin' && fetchSite !== 'none') {
      next(withEvent(new HttpError('forbidden', 'This request came from another website and was blocked.'), 'origin.blocked'));
      return;
    }
    next();
  };
}

/**
 * SecureVibe's session only counts on 127.0.0.1. Browsers send a cookie to every port of the same host, and app
 * previews run on localhost, so a SecureVibe cookie that a browser also holds for localhost is worthless there.
 */
export const SESSION_HOSTNAME = '127.0.0.1';

/**
 * An address on SecureVibe's own sign-in host: `pathAndQuery` can only ever become a path there (leading slashes are
 * collapsed, so "//elsewhere.example" stays a path), and the result is checked to keep that origin.
 */
export function safeUrl(port: number, pathAndQuery: string): string {
  const origin = `http://${SESSION_HOSTNAME}:${port}`;
  const url = `${origin}/${pathAndQuery.replace(/^[/\\]+/, '')}`;
  return new URL(url).origin === origin ? url : `${origin}/`;
}

export function sessionFromRequest(req: Request, sessions: SessionManager): SessionRecord | undefined {
  if (splitHost(req.headers.host ?? '')?.hostname !== SESSION_HOSTNAME) return undefined;
  const cookies = parseCookies(req.headers.cookie);
  return sessions.validate(cookies[SESSION_COOKIE]);
}

/** Requires the session cookie; attaches the session to res.locals.session. */
export function requireSession(sessions: SessionManager): RequestHandler {
  return (req, res, next) => {
    const session = sessionFromRequest(req, sessions);
    if (!session) {
      next(new HttpError('unauthorized', 'Your SecureVibe session is missing or has expired. Open the link printed in the terminal (restart SecureVibe if needed).'));
      return;
    }
    res.locals['session'] = session;
    next();
  };
}

/** Requires X-CSRF-Token to match the session's token on state-changing requests. Runs after requireSession. */
export function csrfCheck(sessions: SessionManager): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!MUTATING.has(req.method)) {
      next();
      return;
    }
    const session = res.locals['session'] as SessionRecord | undefined;
    const presented = req.header(CSRF_HEADER);
    if (!session || !sessions.csrfMatches(session, presented)) {
      next(withEvent(new HttpError('forbidden', 'The request is missing a valid security token. Reload the page and try again.'), 'csrf.rejected'));
      return;
    }
    next();
  };
}

/** Rejects non-JSON bodies on JSON routes so form posts from other sites cannot slip through content-type sniffing. */
export function requireJsonBody(allowRaw: (req: Request) => boolean = () => false): RequestHandler {
  return (req, _res, next) => {
    // A route that takes raw bytes (file uploads) still needs the session and the CSRF token; only the type differs.
    if (allowRaw(req) && /^application\/octet-stream\b/i.test(req.headers['content-type'] ?? '')) {
      next();
      return;
    }
    if (!MUTATING.has(req.method) || req.headers['content-length'] === '0' || req.headers['content-length'] === undefined) {
      if (MUTATING.has(req.method) && req.headers['transfer-encoding'] === undefined && req.headers['content-length'] === undefined) {
        next();
        return;
      }
    }
    if (MUTATING.has(req.method)) {
      const type = req.headers['content-type'] ?? '';
      if (req.headers['content-length'] !== '0' && !/^application\/json\b/i.test(type)) {
        next(new HttpError('validation_error', 'Requests must send JSON (Content-Type: application/json).', undefined, 415));
        return;
      }
    }
    next();
  };
}

/** Ends requests that take longer than `ms` with a timeout error (SSE streams are exempt). */
export function requestTimeout(ms: number): RequestHandler {
  return (req, res, next) => {
    if (req.path.endsWith('/events')) {
      next();
      return;
    }
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(503).json({ error: { code: 'timeout', message: 'The request took too long and was stopped.' } });
      } else {
        res.end();
      }
    }, ms);
    timer.unref();
    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));
    next();
  };
}
