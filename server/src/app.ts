/**
 * The Express app (CONTRACTS §0): local security posture, the API, the SSE progress channel, and the built SPA.
 *
 * Middleware order matters: correlation id and request logging first (every response gets logged, even a
 * rejected one); Host allow-list before anything else looks at the request; headers/CSP next so even an error
 * response carries them; body parsing and rate limiting before validation; Origin/CSRF only on the routes that
 * need a session.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import express, { type Express, type RequestHandler } from 'express';
import helmet from 'helmet';
import rateLimit, { MemoryStore } from 'express-rate-limit';
import type { Knowledge, LlmProvider } from './integration.js';
import type { Frameworks } from './frameworks/index.js';
import { buildApiRouter } from './api/index.js';
import type { SecureVibeConfig } from './config.js';
import { RunBusRegistry } from './pipeline/bus.js';
import { apiNotFoundHandler, errorHandler, HttpError } from './security/errors.js';
import { sessionRef } from './api/approvals.js';
import { isRawUploadRequest } from './api/uploads.js';
import type { Logger } from './security/logger.js';
import { correlationIdMiddleware, requestLogMiddleware } from './security/logger.js';
import { csrfCheck, hostAllowList, originCheck, requireJsonBody, requireSession, requestTimeout, safeUrl, sessionFromRequest, SESSION_HOSTNAME, splitHost } from './security/middleware.js';
import { clearSessionCookieHeader, sessionCookieHeader, type SessionManager } from './security/token.js';
import type { ProjectStore } from './store/index.js';

export interface AppDeps {
  config: SecureVibeConfig;
  sessions: SessionManager;
  logger: Logger;
  store: ProjectStore;
  knowledge: Knowledge;
  frameworks: Frameworks;
  /** Built fresh from current settings whenever a route needs one (a settings change takes effect immediately). */
  getProvider: () => LlmProvider;
  busRegistry: RunBusRegistry;
}

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 600;
/** File uploads: one request per file, so an app of a few thousand files fits in a couple of minutes. */
const UPLOAD_RATE_LIMIT_MAX = 3_000;
const REQUEST_TIMEOUT_MS = 30_000;
const TOKEN_ATTEMPT_WINDOW_MS = 15 * 60_000;
const TOKEN_ATTEMPT_MAX = 10;
const JSON_BODY_LIMIT = '1mb';

/** Strict CSP for SecureVibe's own UI (DESIGN §4.3): nonce-based, no inline scripts, nothing embeddable. */
function cspHeader(nonce: string): string {
  return [
    "default-src 'self'",
    // 'strict-dynamic': only scripts the nonce-bearing entry loads may run (the same policy generated apps use).
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');
}

function nonceMiddleware(): RequestHandler {
  return (_req, res, next) => {
    res.locals['nonce'] = randomBytes(16).toString('base64');
    next();
  };
}

function cspMiddleware(): RequestHandler {
  return (_req, res, next) => {
    res.setHeader('Content-Security-Policy', cspHeader(res.locals['nonce'] as string));
    next();
  };
}

const NO_SESSION_PAGE = (tokenHint: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SecureVibe</title></head>
<body style="font: 16px/1.5 system-ui, sans-serif; max-width: 40em; margin: 4em auto; padding: 0 1em;">
<h1>SecureVibe needs the link it printed</h1>
<p>Your browser does not have a valid SecureVibe session. This keeps other web pages from talking to SecureVibe.</p>
<p>${tokenHint}</p>
</body></html>`;

/** Serves `web/dist/index.html` with `__CSP_NONCE__` replaced by the request's real nonce. */
function serveIndexHtml(webDist: string, port: number): RequestHandler {
  const file = join(webDist, 'index.html');
  return (req, res, next) => {
    const session = res.locals['session'];
    const host = splitHost(req.headers.host ?? '');
    if (!session && host && host.hostname !== SESSION_HOSTNAME) {
      // SecureVibe signs in on 127.0.0.1 only: the same page there may already be signed in.
      res.redirect(302, safeUrl(port, req.originalUrl));
      return;
    }
    if (!session) {
      res
        .status(401)
        .type('text/html')
        .send(NO_SESSION_PAGE('Restart SecureVibe and open the link it prints, or use the link from when you first started it.'));
      return;
    }
    if (!existsSync(file)) {
      res.status(503).type('text/plain').send('The SecureVibe web app has not been built yet. Run "npm run build" in web/, then reload.');
      return;
    }
    try {
      const html = readFileSync(file, 'utf8').replaceAll('__CSP_NONCE__', res.locals['nonce'] as string);
      res.status(200).type('text/html').send(html);
    } catch (err) {
      next(err);
    }
  };
}

export function createApp(deps: AppDeps): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('query parser', 'simple');
  app.set('trust proxy', false);
  app.set('etag', false);

  app.use(correlationIdMiddleware());
  app.use(requestLogMiddleware(deps.logger));
  app.use(hostAllowList({ port: deps.config.port }));
  app.use(nonceMiddleware());
  app.use(
    helmet({
      contentSecurityPolicy: false, // set explicitly by cspMiddleware (needs the per-request nonce)
      crossOriginEmbedderPolicy: false,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      permittedCrossDomainPolicies: false,
    }),
  );
  app.use(cspMiddleware());
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    // Pages and API answers describe private projects: never cache them (static assets set their own header).
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(express.json({ limit: JSON_BODY_LIMIT }));
  // In-memory limiter stores; `app.locals.resetRateLimits` lets the self-assessment's runtime scan start each
  // group of checks from clean counters (it is not reachable over HTTP).
  const rateStores = [new MemoryStore(), new MemoryStore(), new MemoryStore()] as const;
  app.locals['resetRateLimits'] = async (): Promise<void> => {
    await Promise.all(rateStores.map((store) => store.resetAll()));
  };
  app.use(
    rateLimit({
      windowMs: RATE_LIMIT_WINDOW_MS,
      max: RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      store: rateStores[0],
      // An app upload sends one request per file; those have their own, larger allowance below.
      skip: (req) => isRawUploadRequest(req.method, req.path.replace(/^\/api/, '')),
      // Through the error handler, so the refusal is logged like any other.
      handler: (_req, _res, next) => next(new HttpError('rate_limited', 'Too many requests. Wait a minute and try again.')),
    }),
  );
  app.use(
    '/api',
    rateLimit({
      windowMs: RATE_LIMIT_WINDOW_MS,
      max: UPLOAD_RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      store: rateStores[2],
      skip: (req) => !isRawUploadRequest(req.method, req.path),
      handler: (_req, _res, next) => next(new HttpError('rate_limited', 'Too many files at once. Wait a minute and the upload continues.')),
    }),
  );
  app.use(requestTimeout(REQUEST_TIMEOUT_MS));
  app.use(originCheck({ port: deps.config.port }));

  // --- session bootstrap -------------------------------------------------------------------------------------
  // Failed link attempts are limited per client on top of the general limit (the token itself is 256 random bits).
  const tokenAttempts = rateLimit({
    windowMs: TOKEN_ATTEMPT_WINDOW_MS,
    max: TOKEN_ATTEMPT_MAX,
    skipSuccessfulRequests: true,
    store: rateStores[1],
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      deps.logger.warn({ event: 'auth.token_rate_limited', ip: req.ip, correlationId: res.locals['correlationId'] }, 'too many startup-link attempts');
      res.status(429).type('text/html').send(NO_SESSION_PAGE('Too many attempts with a wrong link. Wait a few minutes, then open the link SecureVibe printed.'));
    },
  });
  app.get('/auth/token', tokenAttempts, (req, res) => {
    const token = typeof req.query['t'] === 'string' ? req.query['t'] : undefined;
    // Sessions only exist on 127.0.0.1 (see SESSION_HOSTNAME): send a localhost link there first.
    const host = splitHost(req.headers.host ?? '');
    if (host?.hostname !== SESSION_HOSTNAME) {
      res.redirect(303, safeUrl(deps.config.port, `auth/token?t=${encodeURIComponent(token ?? '')}`));
      return;
    }
    const session = deps.sessions.exchange(token);
    if (!session) {
      deps.logger.warn({ event: 'auth.token_rejected', ip: req.ip, correlationId: res.locals['correlationId'] }, 'startup link refused');
      res
        .status(403)
        .type('text/html')
        .send(NO_SESSION_PAGE('That link is not valid for this SecureVibe session. Restart SecureVibe and open the link it prints.'));
      return;
    }
    deps.logger.info({ event: 'auth.token_accepted', sessionRef: sessionRef(session.id), ip: req.ip, correlationId: res.locals['correlationId'] }, 'signed in with the startup link');
    res.setHeader('Set-Cookie', sessionCookieHeader(session.id));
    res.redirect(303, '/');
  });

  app.post('/auth/logout', requireSession(deps.sessions), csrfCheck(deps.sessions), (req, res) => {
    const session = sessionFromRequest(req, deps.sessions);
    if (session) deps.sessions.revoke(session.id);
    res.setHeader('Set-Cookie', clearSessionCookieHeader());
    res.setHeader('Clear-Site-Data', '"cookies", "storage"');
    res.status(204).end();
  });

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // --- API ----------------------------------------------------------------------------------------------------
  app.use(
    '/api',
    requireSession(deps.sessions),
    csrfCheck(deps.sessions),
    requireJsonBody((r) => isRawUploadRequest(r.method, r.path)),
    buildApiRouter({
      config: deps.config,
      sessions: deps.sessions,
      logger: deps.logger,
      store: deps.store,
      knowledge: deps.knowledge,
      frameworks: deps.frameworks,
      getProvider: deps.getProvider,
      busRegistry: deps.busRegistry,
    }),
  );
  app.use('/api', apiNotFoundHandler);

  // --- the built SPA --------------------------------------------------------------------------------------------
  app.use((req, res, next) => {
    const session = sessionFromRequest(req, deps.sessions);
    if (session) res.locals['session'] = session;
    next();
  });
  app.use(express.static(deps.config.paths.webDist, { index: false, redirect: false }));
  // Express 5: `{*splat}` also matches the bare root path, `*splat` alone does not.
  app.get('/{*splat}', serveIndexHtml(deps.config.paths.webDist, deps.config.port));
  // Anything else (a POST to an unknown path, for example) gets a plain 404 instead of Express's default page.
  app.use((_req, res) => {
    res.status(404).type('text/plain').send('Not found.');
  });

  app.use(errorHandler(deps.logger));
  return app;
}
