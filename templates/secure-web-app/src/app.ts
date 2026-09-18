/**
 * Express app factory. The order of middleware is deliberate: request id and logging first, then security
 * headers, static files, body limits, sessions, rate limiting, account guards, the registry-mounted routes, and
 * finally the 404/405 and error handlers that never leak technical details.
 */
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import express, { type Express, type NextFunction, type Request, type Response, Router } from 'express';
import { z } from 'zod';
import { APP_ROOT, config } from './config.ts';
import { get } from './db/index.ts';
import { registerFeatures } from './features/index.ts';
import { errors, HttpError } from './lib/errors.ts';
import { logger } from './lib/logger.ts';
import { registerTestModeRoutes } from './lib/test-mode.ts';
import { adminMfaGuard, passwordChangeGuard } from './security/authz.ts';
import { emit } from './security/events.ts';
import { authenticatedCacheControl, securityHeaders } from './security/headers.ts';
import { limiter } from './security/rate-limit.ts';
import { assertAllRoutesRegistered, defineRoute, methodsForPath, respondWithError } from './security/routes.ts';
import { sessionMiddleware } from './security/session.ts';

export const BODY_LIMIT = '100kb';
/**
 * Only the methods the route registry can declare (plus HEAD, which Express answers from GET). TRACE, CONNECT and
 * anything else are refused with 405 before any handler runs. OPTIONS is refused too: there is no CORS here, so a
 * preflight has nothing to allow, and Express' automatic OPTIONS reply would otherwise answer for routes that
 * never passed through defineRoute.
 */
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function requestContext(req: Request, res: Response, next: NextFunction): void {
  req.id = randomUUID();
  res.setHeader('X-Request-Id', req.id);
  const started = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
    logger.info(
      {
        reqId: req.id,
        method: req.method,
        route: req.routeSpec ? req.routeSpec.path : req.path.slice(0, 200),
        status: res.statusCode,
        durationMs: Math.round(durationMs * 10) / 10,
        userId: req.user?.id ?? null,
        session: req.session?.logId ?? null,
        ip: req.ip ?? null,
      },
      'request',
    );
  });
  next();
}

function methodFilter(req: Request, res: Response, next: NextFunction): void {
  if (!ALLOWED_METHODS.has(req.method)) {
    res.setHeader('Allow', 'GET, HEAD, POST, PUT, PATCH, DELETE');
    return next(new HttpError(405, 'method_not_allowed', 'This kind of request is not supported.'));
  }
  next();
}

function hasForbiddenKey(value: unknown, depth = 0): boolean {
  if (depth > 10 || value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKey(v, depth + 1));
  for (const key of Object.keys(value as object)) {
    if (FORBIDDEN_KEYS.has(key)) return true;
    if (hasForbiddenKey((value as Record<string, unknown>)[key], depth + 1)) return true;
  }
  return Object.getOwnPropertyNames(value).some((k) => FORBIDDEN_KEYS.has(k));
}

function rejectPrototypePollution(req: Request, _res: Response, next: NextFunction): void {
  if (req.body !== undefined && hasForbiddenKey(req.body)) {
    return next(errors.badRequest('The request contains field names that are not allowed.'));
  }
  if (hasForbiddenKey(req.query)) return next(errors.badRequest('The request contains parameter names that are not allowed.'));
  next();
}

function isLoopback(address: string | undefined): boolean {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

function registerHealthRoutes(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/healthz', auth: 'public', kind: 'api', summary: 'Liveness check' }, (_req, res) => {
    res.json({ status: 'ok' });
  });
  defineRoute(router, { method: 'GET', path: '/readyz', auth: 'public', kind: 'api', summary: 'Readiness check (loopback only)' }, (req, res) => {
    if (!config.BIND_LAN && !isLoopback(req.socket.remoteAddress)) throw errors.notFound();
    try {
      get('SELECT 1 AS ok');
      res.json({ status: 'ready' });
    } catch {
      res.status(503).json({ status: 'not-ready' });
    }
  });
}

function notFoundHandler(req: Request, res: Response, next: NextFunction): void {
  const methods = methodsForPath(req.path);
  if (methods.length > 0 && !methods.includes(req.method as never) && !(req.method === 'HEAD' && methods.includes('GET'))) {
    res.setHeader('Allow', methods.join(', '));
    return next(new HttpError(405, 'method_not_allowed', 'This page does not accept that kind of request.'));
  }
  next(errors.notFound());
}

function bodyParserError(err: Error & { type?: string; status?: number }): HttpError | undefined {
  switch (err.type) {
    case 'entity.parse.failed':
      return new HttpError(400, 'invalid_json', 'The request body is not valid JSON.');
    case 'entity.too.large':
      return new HttpError(413, 'payload_too_large', `The request body is larger than the ${BODY_LIMIT} limit.`);
    case 'parameters.too.many':
      return new HttpError(413, 'payload_too_large', 'The form has too many fields.');
    case 'charset.unsupported':
    case 'encoding.unsupported':
      return new HttpError(415, 'unsupported_media_type', 'That text encoding is not supported.');
    case 'entity.verify.failed':
    case 'request.aborted':
    case 'stream.encoding.set':
    case 'stream.not.readable':
      return new HttpError(400, 'bad_request', 'The request could not be read.');
    default:
      return undefined;
  }
}

/** Errors raised by Express itself or the static file server (403 for dotfiles, 400 for a malformed URL) keep their status. */
function clientErrorFromMiddleware(err: unknown): HttpError | undefined {
  const status = (err as { status?: unknown; statusCode?: unknown }).status ?? (err as { statusCode?: unknown }).statusCode;
  if (typeof status !== 'number' || status < 400 || status >= 500) return undefined;
  switch (status) {
    case 403:
      return errors.forbidden();
    case 404:
      return errors.notFound();
    case 413:
      return new HttpError(413, 'payload_too_large', 'What you sent is larger than this app accepts.');
    case 415:
      return new HttpError(415, 'unsupported_media_type', 'That kind of content is not supported.');
    default:
      return errors.badRequest();
  }
}

function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction): void {
  let httpError: HttpError;
  if (err instanceof HttpError) {
    httpError = err;
  } else {
    const mapped = (err instanceof Error ? bodyParserError(err as Error & { type?: string }) : undefined) ?? clientErrorFromMiddleware(err);
    if (mapped) {
      httpError = mapped;
    } else {
      logger.error({ reqId: req.id, err: err instanceof Error ? { name: err.name, message: err.message, stack: err.stack } : String(err) }, 'unhandled error');
      emit('error.unhandled', { req, reqId: req.id });
      httpError = new HttpError(500, 'internal_error', 'Something went wrong on our side. It has been logged. Please try again in a moment.');
    }
  }
  respondWithError(req, res, httpError, next);
}

export async function createApp(): Promise<Express> {
  const app = express();
  app.set('query parser', 'simple');
  app.set('trust proxy', config.TRUST_PROXY_HOPS);
  app.set('etag', false);
  app.set('x-powered-by', false);
  app.set('views', resolve(APP_ROOT, 'src', 'views'));

  app.use(requestContext);
  // The headers (and the CSP nonce the layout needs) come first so that even a request refused for its method
  // gets a proper, hardened error page.
  app.use(...securityHeaders());
  app.use(methodFilter);
  app.use(
    express.static(resolve(APP_ROOT, 'public'), {
      dotfiles: 'deny',
      index: false,
      redirect: false,
      maxAge: config.NODE_ENV === 'production' ? '1h' : 0,
      setHeaders: (res, path) => {
        if (path.endsWith('.css')) res.setHeader('Content-Type', 'text/css; charset=utf-8');
        else if (path.endsWith('.js')) res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
      },
    }),
  );
  app.use(express.json({ limit: BODY_LIMIT, strict: true, type: 'application/json' }));
  app.use(express.urlencoded({ extended: false, limit: BODY_LIMIT, parameterLimit: 100, type: 'application/x-www-form-urlencoded' }));
  app.use(rejectPrototypePollution);
  app.use(sessionMiddleware());
  app.use(authenticatedCacheControl);
  app.use(limiter('general'));
  app.use(passwordChangeGuard);
  app.use(adminMfaGuard);

  const router = Router();
  registerHealthRoutes(router);
  await registerFeatures(router);
  if (config.testMode) registerTestModeRoutes(router);
  app.use(router);

  assertAllRoutesRegistered(app);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

/** Exposed for tests that want to build a throw-away router with the registry. */
export const schemaHelpers = { z };
