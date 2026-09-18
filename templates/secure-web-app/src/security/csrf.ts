/**
 * Cross-site request forgery protection for every state-changing request:
 *  1. the Origin header (when present) must be this site; Sec-Fetch-Site (when present) must be same-origin/none;
 *  2. a synchronizer token stored in the session must be sent back in the `_csrf` form field or the
 *     `X-CSRF-Token` header and match in constant time.
 * Failures are 403 with a plain message and a `csrf.rejected` event.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { errors } from '../lib/errors.ts';
import { emit } from './events.ts';

export const CSRF_FIELD = '_csrf';
export const CSRF_HEADER = 'x-csrf-token';
export const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Returns the session's token, creating the session (and token) when needed. */
export function csrfToken(req: Request): string {
  const existing = req.session.get<string>('csrf');
  if (existing) return existing;
  const token = randomBytes(32).toString('base64url');
  req.session.set('csrf', token);
  return token;
}

function requestHost(req: Request): string | undefined {
  return req.headers.host?.toLowerCase();
}

/** True when Origin / Sec-Fetch-Site headers show the request came from this site (or from a non-browser client). */
export function passesOriginCheck(req: Request): { ok: boolean; reason?: string } {
  const origin = req.headers.origin;
  if (origin !== undefined) {
    if (origin === 'null') return { ok: false, reason: 'origin-null' };
    let originHost: string;
    try {
      originHost = new URL(origin).host.toLowerCase();
    } catch {
      return { ok: false, reason: 'origin-invalid' };
    }
    if (originHost !== requestHost(req)) return { ok: false, reason: 'origin-mismatch' };
  }
  const fetchSite = req.headers['sec-fetch-site'];
  if (typeof fetchSite === 'string' && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return { ok: false, reason: 'sec-fetch-site' };
  }
  return { ok: true };
}

function presentedToken(req: Request): string | undefined {
  const header = req.headers[CSRF_HEADER];
  if (typeof header === 'string' && header) return header;
  const body = req.body as Record<string, unknown> | undefined;
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const field = body[CSRF_FIELD];
    if (typeof field === 'string') return field;
  }
  return undefined;
}

/** Removes the token field so strict body schemas do not see it. */
export function stripCsrfField(req: Request): void {
  const body = req.body as Record<string, unknown> | undefined;
  if (body && typeof body === 'object' && !Array.isArray(body) && CSRF_FIELD in body) delete body[CSRF_FIELD];
}

export function csrfProtect(req: Request, _res: Response, next: NextFunction): void {
  if (!MUTATING_METHODS.has(req.method)) return next();
  const origin = passesOriginCheck(req);
  if (!origin.ok) {
    emit('csrf.rejected', { req, reason: origin.reason });
    return next(errors.csrf());
  }
  const presented = presentedToken(req);
  const expected = req.session.get<string>('csrf');
  if (!presented || !expected || presented.length !== expected.length || !timingSafeEqual(Buffer.from(presented), Buffer.from(expected))) {
    emit('csrf.rejected', { req, reason: presented ? 'token-mismatch' : 'token-missing' });
    return next(errors.csrf());
  }
  stripCsrfField(req);
  next();
}
