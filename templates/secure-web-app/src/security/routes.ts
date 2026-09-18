/**
 * The route registry — the backbone of the app's security. Every route is declared through defineRoute with:
 *  - an explicit `auth` value (nothing is reachable without one),
 *  - strict zod schemas for params / query / body (unknown fields are rejected),
 *  - CSRF protection on state-changing requests (default on),
 *  - a rate-limit preset, and an optional owner check for records that belong to a user.
 * `assertAllRoutesRegistered()` refuses to start the app if any route bypassed the registry.
 */
import { createHash } from 'node:crypto';
import type { Express, NextFunction, Request, RequestHandler, Response, Router } from 'express';
import { z, type ZodType } from 'zod';
import { get, run } from '../db/index.ts';
import { errors, HttpError } from '../lib/errors.ts';
import { renderErrorPage } from '../lib/views.ts';
import { requireAuth, requireOwner, requireRole } from './authz.ts';
import { csrfProtect, stripCsrfField } from './csrf.ts';
import { emit } from './events.ts';
import { limiter, type RateLimitPreset } from './rate-limit.ts';
import { assertStrictObjectSchema, validate, type FieldErrors } from './validate.ts';

export type Auth = 'public' | 'user' | `role:${string}`;
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface RouteSpec<P = unknown, Q = unknown, B = unknown> {
  method: HttpMethod;
  path: string;
  /** Deny-by-default: who may call this route. */
  auth: Auth;
  /** Additional allowed roles when auth is 'user' (admin always allowed). Empty/undefined = any signed-in user. */
  roles?: string[];
  /** Loads the record by :param and checks ownerField === user.id (admins bypass). */
  owner?: { entity: string; param: string; ownerField?: string };
  schema?: { params?: ZodType<P>; query?: ZodType<Q>; body?: ZodType<B> };
  /** Default true for state-changing methods with session auth; false only for API-key routes. */
  csrf?: boolean;
  rateLimit?: RateLimitPreset;
  /** JSON API mutations honour the Idempotency-Key header (stored response replay). */
  idempotent?: boolean;
  summary?: string;
  entity?: string;
  kind?: 'page' | 'api';
  /** Pages: called with the field errors instead of the generic 400 page (re-render the form). */
  onInvalid?: (req: Request, res: Response, fields: FieldErrors) => Promise<void> | void;
}

export interface ValidatedRequest<P, Q, B> extends Request {
  valid: { params: P; query: Q; body: B };
}

export type RouteHandler<P, Q, B> = (req: ValidatedRequest<P, Q, B>, res: Response) => Promise<void> | void;

const registry: RouteSpec[] = [];
const registeredRouteObjects = new WeakSet<object>();
const EMPTY = z.strictObject({});
const MUTATING = new Set<HttpMethod>(['POST', 'PUT', 'PATCH', 'DELETE']);
const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;

function kindFor(spec: RouteSpec): 'page' | 'api' {
  return spec.kind ?? (spec.path.startsWith('/api/') || spec.path.startsWith('/__securevibe') || spec.path === '/healthz' || spec.path === '/readyz' ? 'api' : 'page');
}

function pathParamNames(path: string): string[] {
  return [...path.matchAll(/:([A-Za-z0-9_]+)/g)].map((m) => m[1] ?? '');
}

function rejectInvalid(spec: RouteSpec, fields: FieldErrors): RequestHandler {
  const kind = kindFor(spec);
  return (req, res, next) => {
    emit('validation.rejected', { req, field: Object.keys(fields).slice(0, 5) });
    if (kind === 'page' && spec.onInvalid) {
      Promise.resolve(spec.onInvalid(req, res, fields)).catch(next);
      return;
    }
    next(errors.validation(fields));
  };
}

/**
 * Validates the route's params and query. This runs before the owner check so the record is looked up with a
 * validated id; the body is validated afterwards (see bodyValidationMiddleware) so a request for somebody
 * else's record is answered the same way whatever the body contains — a validation error must never tell an
 * outsider that the record exists.
 */
function addressValidationMiddleware(spec: RouteSpec): RequestHandler {
  const params = spec.schema?.params ?? EMPTY;
  const query = spec.schema?.query ?? EMPTY;
  return (req, res, next) => {
    // For non-CSRF routes the hidden field may still be present; drop it before strict validation.
    stripCsrfField(req);
    const p = validate(params, req.params, { objectOnly: true });
    const q = validate(query, req.query, { objectOnly: true });
    const fields: FieldErrors = {};
    if (!p.ok) for (const [k, v] of Object.entries(p.fields)) fields[`params.${k}`] = v;
    if (!q.ok) for (const [k, v] of Object.entries(q.fields)) fields[`query.${k}`] = v;
    req.valid = { params: p.ok ? p.data : {}, query: q.ok ? q.data : {}, body: {} };
    if (Object.keys(fields).length > 0) return rejectInvalid(spec, fields)(req, res, next);
    next();
  };
}

/** Validates the request body of a state-changing route (after auth, CSRF and the owner check). */
function bodyValidationMiddleware(spec: RouteSpec): RequestHandler {
  const body = spec.schema?.body ?? EMPTY;
  return (req, res, next) => {
    const b = validate(body, req.body, { objectOnly: true });
    if (!b.ok) return rejectInvalid(spec, b.fields)(req, res, next);
    req.valid = { ...req.valid, body: b.data };
    next();
  };
}

function idempotencyMiddleware(spec: RouteSpec): RequestHandler {
  return (req, res, next) => {
    const header = req.get('Idempotency-Key');
    if (header === undefined) return next();
    if (!/^[A-Za-z0-9_.:-]{1,200}$/.test(header)) return next(errors.badRequest('The Idempotency-Key header must be 1-200 letters, digits, dots, dashes or colons.'));
    const routeKey = `${spec.method} ${spec.path}`;
    const keyHash = createHash('sha256').update(`${req.user?.id ?? 'anon'}|${routeKey}|${header}`).digest('hex');
    const requestHash = createHash('sha256').update(JSON.stringify(req.valid.body ?? null)).digest('hex');
    const existing = get<{ request_hash: string; status: number; body: string }>('SELECT request_hash, status, body FROM idempotency_keys WHERE key_hash = ?', [keyHash]);
    if (existing) {
      if (existing.request_hash !== requestHash) {
        return next(new HttpError(422, 'idempotency_key_reuse', 'This Idempotency-Key was already used with a different request.'));
      }
      res.setHeader('Idempotent-Replayed', 'true');
      res.status(existing.status).type('application/json').send(existing.body);
      return;
    }
    const originalJson = res.json.bind(res);
    res.json = ((payload: unknown) => {
      try {
        run('DELETE FROM idempotency_keys WHERE created_at < ?', [new Date(Date.now() - IDEMPOTENCY_TTL_MS).toISOString()]);
        run('INSERT OR IGNORE INTO idempotency_keys (key_hash, user_id, route, request_hash, status, body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [
          keyHash,
          req.user?.id ?? null,
          routeKey,
          requestHash,
          res.statusCode,
          JSON.stringify(payload),
          new Date().toISOString(),
        ]);
      } catch {
        // A failed replay record must not break the real response.
      }
      return originalJson(payload);
    }) as Response['json'];
    next();
  };
}

/** Registers a route with its full security chain: rate limit → auth → csrf → params/query → owner → body → handler. */
export function defineRoute<P = Record<string, never>, Q = Record<string, never>, B = Record<string, never>>(
  router: Router,
  spec: RouteSpec<P, Q, B>,
  handler: RouteHandler<P, Q, B>,
): void {
  const where = `${spec.method} ${spec.path}`;
  if (!spec.auth) throw new Error(`${where}: every route must declare "auth" ('public', 'user' or 'role:<name>').`);
  if (!/^\/[A-Za-z0-9_\-./:]*$/.test(spec.path)) throw new Error(`${where}: route paths must be simple absolute paths.`);
  const paramNames = pathParamNames(spec.path);
  if (paramNames.length > 0 && !spec.schema?.params) throw new Error(`${where}: routes with path parameters need schema.params.`);
  for (const [name, schema] of Object.entries(spec.schema ?? {})) {
    if (schema) assertStrictObjectSchema(schema as ZodType, `${where} schema.${name}`);
  }
  if (registry.some((r) => r.method === spec.method && r.path === spec.path)) throw new Error(`${where}: this route is already registered.`);

  const kind = kindFor(spec);
  const chain: RequestHandler[] = [];
  const preset = spec.rateLimit ?? 'general';

  chain.push((req, _res, next) => {
    req.routeSpec = spec as RouteSpec;
    next();
  });
  if (preset !== 'general') chain.push(limiter(preset));

  if (spec.auth === 'user') chain.push(requireAuth);
  else if (spec.auth.startsWith('role:')) chain.push(requireAuth, requireRole([spec.auth.slice(5)]));
  if (spec.auth === 'user' && spec.roles && spec.roles.length > 0) chain.push(requireRole(spec.roles));

  const csrf = spec.csrf ?? true;
  if (csrf && MUTATING.has(spec.method)) chain.push(csrfProtect);

  chain.push(addressValidationMiddleware(spec as RouteSpec));
  if (spec.owner) chain.push(requireOwner(spec.owner));
  if (MUTATING.has(spec.method)) chain.push(bodyValidationMiddleware(spec as RouteSpec));
  if (spec.idempotent && kind === 'api' && MUTATING.has(spec.method)) chain.push(idempotencyMiddleware(spec as RouteSpec));

  chain.push((req, res, next) => {
    Promise.resolve(handler(req as ValidatedRequest<P, Q, B>, res)).catch(next);
  });

  const expressMethod = spec.method.toLowerCase() as 'get' | 'post' | 'put' | 'patch' | 'delete';
  router[expressMethod](spec.path, ...chain);
  const stack = (router as unknown as { stack: { route?: object }[] }).stack;
  const last = stack[stack.length - 1];
  if (last?.route) registeredRouteObjects.add(last.route);
  registry.push({ ...(spec as RouteSpec), kind });
}

export function listRoutes(): RouteSpec[] {
  return registry.map((r) => ({ ...r }));
}

/** Serialisable view of the registry (routes.manifest.json, docs, test-mode endpoint). */
export interface RouteSummary {
  method: HttpMethod;
  path: string;
  auth: Auth;
  roles: string[];
  owner: RouteSpec['owner'] | null;
  entity: string | null;
  kind: 'page' | 'api';
  csrf: boolean;
  rateLimit: RateLimitPreset;
  idempotent: boolean;
  summary: string;
  params: string[];
}

export function summariseRoutes(): RouteSummary[] {
  return registry.map((r) => ({
    method: r.method,
    path: r.path,
    auth: r.auth,
    roles: r.roles ?? [],
    owner: r.owner ?? null,
    entity: r.entity ?? null,
    kind: r.kind ?? 'page',
    csrf: (r.csrf ?? true) && MUTATING.has(r.method),
    rateLimit: r.rateLimit ?? 'general',
    idempotent: r.idempotent ?? false,
    summary: r.summary ?? '',
    params: pathParamNames(r.path),
  }));
}

/** JSON Schema (draft 2020-12) for each route's validated inputs; used by docs/validation.md and openapi.json. */
export function routeSchemasAsJson(): { method: HttpMethod; path: string; params?: unknown; query?: unknown; body?: unknown }[] {
  // Input side of each schema (what a client must send); transforms such as trim/lower-case have no JSON form.
  const toJson = (schema: ZodType | undefined) => (schema ? z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' }) : undefined);
  return registry.map((r) => ({
    method: r.method,
    path: r.path,
    params: toJson(r.schema?.params as ZodType | undefined),
    query: toJson(r.schema?.query as ZodType | undefined),
    body: toJson(r.schema?.body as ZodType | undefined),
  }));
}

interface Layer {
  route?: { path: string; methods: Record<string, boolean> };
  handle?: { stack?: Layer[] };
  name?: string;
}

function walk(stack: Layer[] | undefined, found: string[]): void {
  for (const layer of stack ?? []) {
    if (layer.route) {
      if (!registeredRouteObjects.has(layer.route)) found.push(`${Object.keys(layer.route.methods).join(',').toUpperCase()} ${layer.route.path}`);
    } else if (layer.handle?.stack) {
      walk(layer.handle.stack, found);
    }
  }
}

/** Throws when the app has any route that was not created through defineRoute. */
export function assertAllRoutesRegistered(app: Express): void {
  const found: string[] = [];
  walk((app as unknown as { router?: { stack?: Layer[] } }).router?.stack, found);
  if (found.length > 0) {
    throw new Error(`These routes bypass the route registry and have no authorization declaration: ${found.join('; ')}`);
  }
}

/** Returns the list of registered methods for a concrete request path (for 405 responses). */
export function methodsForPath(path: string): HttpMethod[] {
  const methods = new Set<HttpMethod>();
  for (const r of registry) {
    const pattern = new RegExp(`^${r.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:[A-Za-z0-9_]+/g, '[^/]+')}/?$`);
    if (pattern.test(path)) methods.add(r.method);
  }
  return [...methods];
}

/** Express-style error rendering shared by the 404 and error handlers (kept here so app.ts stays small). */
export function respondWithError(req: Request, res: Response, err: HttpError, next?: NextFunction): void {
  if (res.headersSent) {
    if (next) next(err);
    return;
  }
  if (err.retryAfterSeconds !== undefined) res.setHeader('Retry-After', String(err.retryAfterSeconds));
  const wantsJson = req.routeSpec?.kind === 'api' || req.path.startsWith('/api/') || req.path.startsWith('/__securevibe') || req.accepts(['html', 'json']) === 'json';
  if (wantsJson) {
    res.status(err.status).json({ error: { code: err.code, message: err.message, ...(err.fields ? { fields: err.fields } : {}) } });
    return;
  }
  renderErrorPage(req, res, err.status, err.message, err.fields);
}
