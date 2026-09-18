/**
 * Authorization: deny by default. Routes declare who may use them (`auth`), which roles are allowed, and whether
 * the record must belong to the signed-in user (`owner`). Administrators pass role and owner checks. Every denial
 * is logged as `authz.denied`.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { config } from '../config.ts';
import { get } from '../db/index.ts';
import { errors, HttpError } from '../lib/errors.ts';
import { emit } from './events.ts';
import { safeLocalPath } from './redirect.ts';

/** Entities that have an owner. Feature modules register theirs so owner checks, exports and test seeding work. */
export interface EntityDefinition {
  name: string;
  table: string;
  idColumn?: string;
  ownerField: string;
  label?: string;
  /** Column names holding sensitive data (redacted in logs, listed in docs/data-protection.md). */
  sensitiveFields?: string[];
  /** Test mode: create one sample record owned by the given user. */
  seed?: (ownerId: string) => void;
  /** Test mode: id of a record owned by the given user (for DAST ownership probes). */
  sampleId?: (ownerId: string) => string | undefined;
  /** Account data export: everything this entity stores about the user. */
  exportForUser?: (userId: string) => unknown;
  /** Account deletion: remove or anonymise this entity's records for the user. */
  deleteForUser?: (userId: string) => void;
}

const entities = new Map<string, EntityDefinition>();
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/i;

export function registerEntity(def: EntityDefinition): void {
  if (!IDENTIFIER.test(def.table) || !IDENTIFIER.test(def.ownerField) || !IDENTIFIER.test(def.idColumn ?? 'id')) {
    throw new Error(`Entity "${def.name}": table and column names must be plain identifiers.`);
  }
  entities.set(def.name, def);
}

export function getEntity(name: string): EntityDefinition | undefined {
  return entities.get(name);
}

export function listEntities(): EntityDefinition[] {
  return [...entities.values()];
}

function wantsJson(req: Request): boolean {
  return req.routeSpec?.kind === 'api' || req.path.startsWith('/api/');
}

/** Records the denial and passes the matching error on. */
export function forbid(req: Request, next: NextFunction, options: { reason: string; resourceId?: string; status?: 401 | 403 | 404 }): void {
  emit('authz.denied', { req, reason: options.reason, resourceId: options.resourceId, userId: req.user?.id ?? null });
  if (options.status === 404) return next(errors.notFound());
  if (options.status === 401) return next(errors.unauthenticated());
  next(errors.forbidden());
}

function redirectToLogin(req: Request, res: Response): void {
  const next = safeLocalPath(req.originalUrl);
  res.redirect(303, `/login?next=${encodeURIComponent(next)}`);
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (req.user) return next();
  emit('authz.denied', { req, reason: 'anonymous', userId: null });
  if (wantsJson(req)) return next(errors.unauthenticated());
  redirectToLogin(req, res);
}

/** Allows the listed roles (administrators are always allowed). */
export function requireRole(roles: readonly string[]): RequestHandler {
  return (req, _res, next) => {
    if (!req.user) return forbid(req, next, { reason: 'anonymous', status: 401 });
    if (req.user.isAdmin || roles.includes(req.user.role)) return next();
    forbid(req, next, { reason: 'wrong-role' });
  };
}

/** Loads the record by its route param and checks it belongs to the signed-in user (admins bypass). */
export function requireOwner(spec: { entity: string; param: string; ownerField?: string }): RequestHandler {
  return (req, _res, next) => {
    if (!req.user) return forbid(req, next, { reason: 'anonymous', status: 401 });
    const def = entities.get(spec.entity);
    if (!def) return next(new Error(`Route declares owner check for unknown entity "${spec.entity}".`));
    const params = req.valid?.params as Record<string, unknown> | undefined;
    const id = params?.[spec.param] ?? req.params[spec.param];
    if (typeof id !== 'string') return forbid(req, next, { reason: 'missing-id', status: 404 });
    const idColumn = def.idColumn ?? 'id';
    const ownerField = spec.ownerField ?? def.ownerField;
    const row = get<Record<string, unknown>>(`SELECT * FROM ${def.table} WHERE ${idColumn} = ?`, [id]);
    if (!row) return forbid(req, next, { reason: 'not-found', resourceId: id, status: 404 });
    if (row[ownerField] !== req.user.id && !req.user.isAdmin) {
      return forbid(req, next, { reason: 'not-owner', resourceId: id, status: 404 });
    }
    req.entity = row;
    next();
  };
}

export const PASSWORD_CHANGE_PATH = '/account/password';
const PASSWORD_CHANGE_ALLOWED = new Set([PASSWORD_CHANGE_PATH, '/logout', '/login', '/healthz', '/readyz']);

/** Users who must change their password can only reach the change-password page until they do. */
export function passwordChangeGuard(req: Request, res: Response, next: NextFunction): void {
  if (!req.user?.mustChangePassword) return next();
  if (PASSWORD_CHANGE_ALLOWED.has(req.path) || req.path.startsWith('/css/') || req.path.startsWith('/js/')) return next();
  if (wantsJson(req)) return next(new HttpError(403, 'password_change_required', 'Please change your password first.'));
  res.redirect(303, PASSWORD_CHANGE_PATH);
}

/** Administrators must enrol a one-time code app before using the app when ADMIN_MFA_REQUIRED=1. */
const MFA_ENROL_ALLOWED = new Set(['/account/mfa/enrol', '/account/mfa/confirm', '/account/reauth', '/logout', PASSWORD_CHANGE_PATH, '/healthz', '/readyz']);

export function adminMfaGuard(req: Request, res: Response, next: NextFunction): void {
  if (!req.user || !config.ADMIN_MFA_REQUIRED || !req.user.isAdmin || req.user.mfaEnrolled) return next();
  if (MFA_ENROL_ALLOWED.has(req.path) || req.path.startsWith('/css/') || req.path.startsWith('/js/')) return next();
  if (wantsJson(req)) return next(errors.forbidden('Administrators must set up a one-time code app first.'));
  req.session.flash('info', 'As an administrator you need to set up one-time codes before continuing.');
  res.redirect(303, '/account/mfa/enrol');
}
