/**
 * API keys for the JSON API (contract §1.12, TPL-APIKEY-01). Create/revoke pages under `/account/api-keys` (and
 * an admin overview), plus a Bearer-only authentication path for `kind: 'api'` routes: a valid key stands in for
 * a signed-in user on those routes, session cookies keep working everywhere else, and a key presented in the
 * query string is always rejected.
 *
 * The Bearer check has to run before *every* route — including ones other feature modules registered earlier,
 * such as the reference "notes" API — so it is spliced to the very front of the shared router's middleware stack
 * (the same reflection `src/security/routes.ts` already uses to walk that stack), rather than appended with a
 * plain `router.use()`, which would only apply to routes registered after this module.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { clampLimit } from '../../db/index.ts';
import { errors } from '../../lib/errors.ts';
import { renderPage } from '../../lib/views.ts';
import { findUserById, toSessionUser } from '../auth/repo.ts';
import { defineRoute, listRoutes } from '../../security/routes.ts';
import { emit } from '../../security/events.ts';
import { hit, presetDefinitions } from '../../security/rate-limit.ts';
import { schemas } from '../../security/validate.ts';
import { createApiKey, findKeyByPrefix, getKey, hashApiKey, listAllKeys, listKeysForUser, parseApiKey, registerApiKeysEntity, revokeKey, toAdminDto, toOwnerDto, touchLastUsed } from './repo.ts';

const CreateBody = z.strictObject({ label: z.string().trim().max(80).optional() });
const KeyParams = z.strictObject({ id: schemas.id });
const AdminQuery = z.strictObject({ page: schemas.page });
const OWNER = { entity: 'apikey', param: 'id', ownerField: 'user_id' } as const;

/** Query-string names a client might mistakenly (or maliciously) try, instead of the Authorization header. */
const FORBIDDEN_QUERY_PARAMS = ['api_key', 'apikey', 'apiKey', 'key', 'token', 'access_token'];

/**
 * A key may be used on any route the registry declares as `kind: 'api'` (contract §1.12), not only on paths
 * under /api/ — `/account/export`, for example, is a JSON route too. The middleware runs before routing, so the
 * registry's path patterns are compiled once into matchers here.
 */
let apiMatchers: RegExp[] | undefined;

function apiRouteMatchers(): RegExp[] {
  if (!apiMatchers) {
    apiMatchers = listRoutes()
      .filter((r) => r.kind === 'api')
      .map((r) => new RegExp(`^${r.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:[A-Za-z0-9_]+/g, '[^/]+')}/?$`));
  }
  return apiMatchers;
}

function isApiPath(path: string): boolean {
  if (path.startsWith('/api/')) return true;
  return apiRouteMatchers().some((re) => re.test(path));
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Authenticates `Authorization: Bearer sk_...` requests to JSON API routes as their key's owner. Runs before the
 * route registry's own `requireAuth`, so a valid key satisfies `auth: 'user'` exactly like a session cookie does.
 *
 * Two things a route's own chain cannot see this early are handled here as well: a key presented in the query
 * string is refused outright (V14.2.1), and — because a Bearer caller has no session and therefore no real
 * synchronizer token — a matching CSRF pair is placed in this request's own (unsaved, never persisted) session
 * data so the shared route's ordinary CSRF check passes without ever creating a session row or a cookie for what
 * the contract calls "not a session".
 */
function bearerAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  const apiPath = isApiPath(req.path);
  if (apiPath) {
    for (const param of FORBIDDEN_QUERY_PARAMS) {
      if (param in req.query) {
        return next(errors.badRequest('API keys must be sent as an "Authorization: Bearer" header, never in the URL.'));
      }
    }
  }
  // Keys authenticate JSON API routes only (contract §1.12); a Bearer header on an ordinary page is ignored so
  // pages keep behaving exactly as they do for an anonymous visitor.
  if (!apiPath) return next();

  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return next();
  const parsed = parseApiKey(header.slice(7));
  if (!parsed) return next(); // Not something that looks like one of our keys; let normal (session) auth decide.

  const row = findKeyByPrefix(parsed.prefix);
  if (!row || row.revoked_at) return next(errors.unauthenticated('This API key is not valid or has been revoked.'));
  const expected = hashApiKey(`sk_${parsed.prefix}_${parsed.secret}`);
  if (!timingSafeEqualHex(row.hash, expected)) return next(errors.unauthenticated('This API key is not valid or has been revoked.'));
  const user = findUserById(row.user_id);
  if (!user || user.status !== 'active') return next(errors.unauthenticated('This API key is not valid or has been revoked.'));

  const def = presetDefinitions()['api-key'];
  const decision = hit(`api-key:key:${row.prefix}`, def.perUser ?? 120, def.windowMs);
  if (!decision.allowed) {
    res.setHeader('Retry-After', String(decision.retryAfterSeconds));
    emit('ratelimit.hit', { req, bucket: 'api-key' });
    return next(errors.rateLimited(decision.retryAfterSeconds));
  }

  req.user = toSessionUser(user);
  touchLastUsed(row.id);

  const bypassToken = randomBytes(16).toString('hex');
  req.headers['x-csrf-token'] = bypassToken;
  // `session.data` is a private field on SessionHandle; writing it directly (rather than through `set()`) keeps
  // this pairing in memory for the lifetime of this request only — no database row, no Set-Cookie header.
  (req.session as unknown as { data: Record<string, unknown> }).data['csrf'] = bypassToken;
  next();
}

/** Moves the just-registered middleware to the front of `router`'s stack so it runs before every route. */
function installBearerAuthFirst(router: Router): void {
  const stack = (router as unknown as { stack: unknown[] }).stack;
  router.use(bearerAuthMiddleware);
  const layer = stack.pop();
  if (layer) stack.unshift(layer);
}

export function register(router: Router): void {
  registerApiKeysEntity();
  installBearerAuthFirst(router);

  defineRoute(router, { method: 'GET', path: '/account/api-keys', auth: 'user', entity: 'apikey', summary: 'Your API keys' }, (req, res) => {
    renderPage(req, res, 'account/api-keys', { title: 'API keys', keys: listKeysForUser(req.user!.id).map(toOwnerDto), created: null });
  });

  defineRoute(
    router,
    { method: 'POST', path: '/account/api-keys', auth: 'user', entity: 'apikey', schema: { body: CreateBody }, summary: 'Create an API key' },
    (req, res) => {
      const { row, fullKey } = createApiKey(req.user!.id, req.valid.body.label || null);
      renderPage(req, res, 'account/api-keys', { title: 'API keys', keys: listKeysForUser(req.user!.id).map(toOwnerDto), created: { ...toOwnerDto(row), fullKey } }, 201);
    },
  );

  defineRoute(
    router,
    { method: 'POST', path: '/account/api-keys/:id/revoke', auth: 'user', owner: OWNER, entity: 'apikey', schema: { params: KeyParams }, summary: 'Revoke an API key' },
    (req, res) => {
      // The owner check above already loaded and verified this row.
      const key = req.entity as unknown as { id: string };
      revokeKey(key.id);
      req.session.flash('success', 'The API key was revoked. It can no longer be used.');
      res.redirect(303, '/account/api-keys');
    },
  );

  defineRoute(router, { method: 'GET', path: '/admin/api-keys', auth: 'role:admin', entity: 'apikey', schema: { query: AdminQuery }, summary: 'All API keys' }, (req, res) => {
    const limit = clampLimit(50);
    const { page } = req.valid.query;
    const keys = listAllKeys(limit, (page - 1) * limit).map(toAdminDto);
    renderPage(req, res, 'admin/api-keys', { title: 'API keys', keys, page, hasMore: keys.length === limit });
  });
  defineRoute(
    router,
    { method: 'POST', path: '/admin/api-keys/:id/revoke', auth: 'role:admin', entity: 'apikey', schema: { params: KeyParams }, summary: 'Revoke any API key' },
    (req, res) => {
      const key = getKey(req.valid.params.id);
      if (!key) throw errors.notFound();
      revokeKey(key.id);
      req.session.flash('success', 'The API key was revoked.');
      res.redirect(303, '/admin/api-keys');
    },
  );
}
