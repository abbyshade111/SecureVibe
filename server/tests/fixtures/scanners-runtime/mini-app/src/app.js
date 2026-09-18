/**
 * Fixture application for the runtime-scanner tests.
 *
 * It is deliberately the smallest thing that honours the contracts the DAST harness depends on:
 *  - CONTRACTS §1.16 test-bootstrap mode: seeded accounts per role (the administrator with a one-time code
 *    derived from SECUREVIBE_TEST_TOTP_SEED), `/__securevibe/routes`, `/__securevibe/events`,
 *    `/__securevibe/reset-rate-limits`, and exactly one JSON ready line on stdout (printed by server.js);
 *  - CONTRACTS §1.5 security headers, §1.6 session cookie rules, a synchronizer CSRF token with an Origin check,
 *    deny-by-default authorization with an owner-scoped entity, anti-automation on sign-in, and a generic
 *    error model.
 *
 * It is not the real template — it exists so the harness, the runner and the probes can be tested without one.
 * `createApp` takes its environment as an argument so a test can run several configurations side by side.
 */
import crypto from 'node:crypto';
import express from 'express';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_ROLE, ROLES, ROUTES, findRoute, methodsForPath } from './routes.js';
import { verifyTotp } from './totp.js';

const APP_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');

const ERROR_CODES = {
  400: 'validation_error',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'method_not_allowed',
  413: 'payload_too_large',
  415: 'unsupported_media_type',
  429: 'too_many_requests',
  500: 'internal_error',
};

const ERROR_MESSAGES = {
  400: 'That request was not in the expected shape.',
  401: 'You need to sign in first.',
  403: 'You are not allowed to do that.',
  404: 'That page does not exist.',
  405: 'That action is not available here.',
  413: 'That request was too large.',
  415: 'That content type is not accepted here.',
  429: 'Too many attempts. Please wait and try again.',
  500: 'Something went wrong. Please try again.',
};

const UNSAFE_KEYS = /^(__proto__|constructor|prototype)$/;
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const LIMITS = { login: 10, 'login-ip': 60, mfa: 10, reset: 10 };
const WINDOW_MS = 15 * 60_000;

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function readCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

export function createApp(env = process.env) {
  const testMode = env.NODE_ENV === 'test' && env.SECUREVIBE_TEST_MODE === '1';
  const tlsMode = env.TLS_MODE ?? 'off';
  const trustProxyHops = Number(env.TRUST_PROXY_HOPS ?? 0);
  const dataDir = env.DATA_DIR ?? join(APP_DIR, 'data');
  const testPassword = env.SECUREVIBE_TEST_PASSWORD ?? '';
  const totpSeed = env.SECUREVIBE_TEST_TOTP_SEED ?? '';
  const secureCookies = tlsMode !== 'off';
  const cookieName = secureCookies ? '__Host-sid' : 'sid';

  mkdirSync(dataDir, { recursive: true });

  // --- state -------------------------------------------------------------------------------------

  const users = [];
  const notes = [];
  const sessions = new Map();
  const events = [];
  const idempotency = new Map();
  const limiterCounts = new Map();
  let seededNoteId = null;

  const addUser = (email, role, mfa) => {
    const user = { id: crypto.randomUUID(), email, role, mfa };
    users.push(user);
    return user;
  };

  if (testMode) {
    addUser('admin@test.local', ADMIN_ROLE, true);
    addUser('staff@test.local', 'staff', false);
    const member = addUser('member@test.local', 'member', false);
    addUser('member2@test.local', 'member', false);
    const note = { id: crypto.randomUUID(), owner_id: member.id, title: 'First note', body: 'Seeded for the runtime scanner.' };
    notes.push(note);
    seededNoteId = note.id;
  }

  // --- helpers -----------------------------------------------------------------------------------

  const clientIp = (req) => {
    if (trustProxyHops > 0) {
      const chain = (req.get('x-forwarded-for') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
      const hop = chain[chain.length - trustProxyHops];
      if (hop) return hop;
    }
    return req.socket.remoteAddress ?? '127.0.0.1';
  };

  const record = (req, event, outcome, extra = {}) => {
    events.push({
      ts: new Date().toISOString(),
      event,
      reqId: req.reqId,
      userId: req.session?.userId ?? null,
      ip: clientIp(req),
      route: req.path,
      outcome,
      ...extra,
    });
    if (events.length > 500) events.splice(0, events.length - 500);
  };

  const isApi = (req) => req.path.startsWith('/api/') || (req.get('accept') ?? '').includes('application/json');

  const layout = (req, title, body) => {
    const nonce = req.res?.locals?.nonce ?? '';
    const token = req.session?.csrf ?? '';
    const logout = req.session?.userId
      ? `<form action="/logout" method="post"><input type="hidden" name="_csrf" value="${escapeHtml(token)}"><button type="submit">Sign out</button></form>`
      : '';
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<meta name="csrf-token" content="${escapeHtml(token)}">
<link rel="stylesheet" href="/css/app.css"></head>
<body><nav>${logout}</nav><main>${body}</main>
<script nonce="${escapeHtml(nonce)}" src="/js/app.js"></script></body></html>`;
  };

  const sendError = (req, res, status, code) => {
    const finalCode = code ?? ERROR_CODES[status] ?? 'error';
    const message = ERROR_MESSAGES[status] ?? 'Something went wrong.';
    if (isApi(req)) {
      res.status(status).json({ error: { code: finalCode, message } });
      return true;
    }
    res.status(status).type('html').send(layout(req, 'Sorry', `<h1>Sorry</h1><p>${escapeHtml(message)}</p>`));
    return true;
  };

  const csrfField = (req) => `<input type="hidden" name="_csrf" value="${escapeHtml(req.session?.csrf ?? '')}">`;

  // --- sessions ----------------------------------------------------------------------------------

  const newSessionId = () => crypto.randomBytes(32).toString('base64url');

  const createSession = () => {
    const session = { id: newSessionId(), userId: null, pendingUserId: null, csrf: crypto.randomBytes(32).toString('base64url') };
    sessions.set(session.id, session);
    return session;
  };

  const setSessionCookie = (res, session) => {
    const attrs = [`${cookieName}=${session.id}`, 'HttpOnly', 'SameSite=Strict', 'Path=/'];
    if (secureCookies) attrs.push('Secure');
    res.append('Set-Cookie', attrs.join('; '));
  };

  const clearSessionCookie = (res) => {
    const attrs = [`${cookieName}=`, 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=0'];
    if (secureCookies) attrs.push('Secure');
    res.append('Set-Cookie', attrs.join('; '));
  };

  /** Replaces the session id but keeps the data: session fixation is the attack this prevents. */
  const rotateSession = (req, res, changes) => {
    sessions.delete(req.session.id);
    const rotated = { ...req.session, ...changes, id: newSessionId(), csrf: crypto.randomBytes(32).toString('base64url') };
    sessions.set(rotated.id, rotated);
    req.session = rotated;
    setSessionCookie(res, rotated);
    return rotated;
  };

  const userOf = (session) => (session?.userId ? users.find((u) => u.id === session.userId) : undefined);

  // --- rate limits -------------------------------------------------------------------------------

  const limiterHit = (bucket, key) => {
    const id = `${bucket}:${key}`;
    const now = Date.now();
    const entry = limiterCounts.get(id);
    if (!entry || now - entry.since > WINDOW_MS) {
      limiterCounts.set(id, { count: 1, since: now });
      return false;
    }
    entry.count += 1;
    return entry.count > (LIMITS[bucket] ?? 100);
  };

  const limiterExceeded = (bucket, key) => {
    const entry = limiterCounts.get(`${bucket}:${key}`);
    return Boolean(entry && Date.now() - entry.since <= WINDOW_MS && entry.count > (LIMITS[bucket] ?? 100));
  };

  // --- validation --------------------------------------------------------------------------------

  const reject = (req, res, field, why) => {
    record(req, 'validation.rejected', 'blocked', { field, why });
    sendError(req, res, 400, 'validation_error');
    return true;
  };

  const validate = (req, res, allowed, required) => {
    const body = req.body ?? {};
    const fields = [];
    for (const key of Object.getOwnPropertyNames(body)) {
      if (UNSAFE_KEYS.test(key)) return reject(req, res, key, 'that name is not allowed');
      if (!allowed.includes(key)) return reject(req, res, key, 'unknown field');
      if (typeof body[key] !== 'string') return reject(req, res, key, 'expected a single text value');
      fields.push(key);
    }
    for (const key of required) {
      if (!fields.includes(key)) return reject(req, res, key, 'missing');
    }
    return false;
  };

  // --- middleware --------------------------------------------------------------------------------

  const app = express();
  app.set('query parser', 'simple');
  app.set('x-powered-by', false);
  app.set('etag', false);
  app.set('trust proxy', trustProxyHops);

  app.use((req, res, next) => {
    req.reqId = crypto.randomBytes(8).toString('hex');
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    const csp = [
      "default-src 'self'",
      `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'`,
      `style-src 'self' 'nonce-${res.locals.nonce}'`,
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ];
    if (tlsMode !== 'off') csp.push('upgrade-insecure-requests');
    res.setHeader('Content-Security-Policy', csp.join('; '));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    if (tlsMode !== 'off') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });

  // Repeated or unsafe query parameters are refused before anything reads them.
  app.use((req, res, next) => {
    const mark = req.url.indexOf('?');
    if (mark < 0) return next();
    const params = new URLSearchParams(req.url.slice(mark + 1));
    const seen = new Set();
    for (const key of params.keys()) {
      if (UNSAFE_KEYS.test(key) || key.includes('__proto__')) return sendError(req, res, 400, 'validation_error');
      if (seen.has(key)) return sendError(req, res, 400, 'validation_error');
      seen.add(key);
    }
    return next();
  });

  app.use(express.static(join(APP_DIR, 'public'), { dotfiles: 'deny', index: false, redirect: false }));

  // A known path asked for with a method it does not support is 405, decided before any body or token check.
  app.use((req, res, next) => {
    if (req.path.startsWith('/__securevibe/')) return next();
    if (findRoute(req.method === 'HEAD' ? 'GET' : req.method, req.path)) return next();
    const allowed = methodsForPath(req.path);
    if (allowed.length === 0) return next();
    res.setHeader('Allow', allowed.join(', '));
    return sendError(req, res, 405, 'method_not_allowed');
  });

  app.use(express.urlencoded({ extended: false, limit: '100kb' }));
  app.use(express.json({ limit: '100kb' }));

  // Every visitor gets a session so the CSRF token has somewhere to live.
  app.use((req, res, next) => {
    const cookies = readCookies(req.get('cookie'));
    const existing = cookies[cookieName] ? sessions.get(cookies[cookieName]) : undefined;
    if (existing) {
      req.session = existing;
    } else {
      req.session = createSession();
      setSessionCookie(res, req.session);
    }
    if (req.session.userId) res.setHeader('Cache-Control', 'no-store, private');
    next();
  });

  app.use((req, res, next) => {
    if (!STATE_CHANGING.has(req.method)) return next();
    if (req.path.startsWith('/__securevibe/')) return next();
    const origin = req.get('origin');
    const site = (req.get('sec-fetch-site') ?? '').toLowerCase();
    const expectedOrigin = `${req.protocol}://${req.get('host')}`;
    if (origin && origin !== expectedOrigin) {
      record(req, 'csrf.rejected', 'blocked', { reason: 'origin' });
      return sendError(req, res, 403, 'forbidden');
    }
    if (site && site !== 'same-origin' && site !== 'none') {
      record(req, 'csrf.rejected', 'blocked', { reason: 'sec-fetch-site' });
      return sendError(req, res, 403, 'forbidden');
    }
    const supplied = (req.body && typeof req.body._csrf === 'string' ? req.body._csrf : undefined) ?? req.get('x-csrf-token');
    if (!supplied || supplied !== req.session.csrf) {
      record(req, 'csrf.rejected', 'blocked', { reason: 'token' });
      return sendError(req, res, 403, 'forbidden');
    }
    if (req.body && typeof req.body === 'object') delete req.body._csrf;
    return next();
  });

  // --- authorization helpers ---------------------------------------------------------------------

  const requireAuth = (req, res) => {
    if (req.session.userId) return false;
    record(req, 'authz.denied', 'blocked', { reason: 'no-session' });
    if (isApi(req)) sendError(req, res, 401, 'unauthorized');
    else res.redirect(303, '/login');
    return true;
  };

  const requireRole = (req, res, role) => {
    if (requireAuth(req, res)) return true;
    if (userOf(req.session)?.role === role) return false;
    record(req, 'authz.denied', 'blocked', { reason: 'wrong-role', required: role });
    sendError(req, res, 403, 'forbidden');
    return true;
  };

  const ownedNote = (req, res) => {
    const note = notes.find((n) => n.id === req.params.id);
    const user = userOf(req.session);
    if (!note) {
      sendError(req, res, 404, 'not_found');
      return null;
    }
    if (note.owner_id !== user?.id && user?.role !== ADMIN_ROLE) {
      record(req, 'authz.denied', 'blocked', { reason: 'not-owner', resourceId: note.id });
      sendError(req, res, 403, 'forbidden');
      return null;
    }
    return note;
  };

  // --- test-bootstrap endpoints ------------------------------------------------------------------

  if (testMode) {
    app.get('/__securevibe/routes', (req, res) => {
      res.json({
        routes: ROUTES,
        roles: ROLES,
        adminRole: ADMIN_ROLE,
        entities: [{ name: 'note', ownerField: 'owner_id', sample: { id: seededNoteId } }],
        seededUsers: users.map((u) => ({ email: u.email, role: u.role, mfa: u.mfa })),
      });
    });

    app.get('/__securevibe/events', (req, res) => {
      const since = typeof req.query.since === 'string' ? req.query.since : '1970-01-01T00:00:00.000Z';
      res.json({ events: events.filter((e) => e.ts >= since).slice(-500) });
    });

    app.post('/__securevibe/reset-rate-limits', (req, res) => {
      limiterCounts.clear();
      res.json({ status: 'ok' });
    });
  }

  // --- public routes -----------------------------------------------------------------------------

  app.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.get('/readyz', (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (!/^(::1|::ffff:127\.|127\.)/.test(ip)) return sendError(req, res, 404, 'not_found');
    return res.json({ status: 'ready' });
  });

  app.get('/', (req, res) => {
    res.type('html').send(layout(req, 'Home', '<h1>Mini app</h1><p>A very small application used to test the runtime scanner.</p>'));
  });

  const loginPage = (req, message = '') =>
    layout(
      req,
      'Sign in',
      `<h1>Sign in</h1>${message ? `<p class="error">${escapeHtml(message)}</p>` : ''}
<form action="/login" method="post">${csrfField(req)}
<label>Email <input type="email" name="email" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form>`,
    );

  app.get('/login', (req, res) => {
    res.type('html').send(loginPage(req));
  });

  app.post('/login', (req, res) => {
    if (validate(req, res, ['_csrf', 'email', 'password', 'next'], ['email', 'password'])) return;
    const email = String(req.body.email ?? '').toLowerCase();
    const ip = clientIp(req);
    if (limiterExceeded('login', email) || limiterExceeded('login-ip', ip)) {
      record(req, 'ratelimit.hit', 'blocked', { bucket: 'login' });
      res.setHeader('Retry-After', '900');
      return sendError(req, res, 429, 'too_many_requests');
    }
    const user = users.find((u) => u.email === email);
    const supplied = Buffer.from(String(req.body.password ?? ''));
    const expected = Buffer.from(testPassword || crypto.randomBytes(24).toString('base64url'));
    // The same work for a known and an unknown account, so timing does not reveal which is which.
    const matches = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
    if (!user || !matches) {
      const overAccount = limiterHit('login', email);
      const overIp = limiterHit('login-ip', ip);
      record(req, 'auth.login.failure', 'failure', { reason: 'bad-credentials' });
      if (overAccount || overIp) {
        record(req, 'ratelimit.hit', 'blocked', { bucket: 'login' });
        res.setHeader('Retry-After', '900');
        return sendError(req, res, 429, 'too_many_requests');
      }
      return res.status(401).type('html').send(loginPage(req, 'Email or password is not correct.'));
    }
    if (user.mfa) {
      rotateSession(req, res, { userId: null, pendingUserId: user.id });
      return res.redirect(303, '/login/mfa');
    }
    rotateSession(req, res, { userId: user.id, pendingUserId: null });
    record(req, 'auth.login.success', 'success', { factor: 'password' });
    return res.redirect(303, '/account');
  });

  const mfaPage = (req, message = '') =>
    layout(
      req,
      'One-time code',
      `<h1>One-time code</h1>${message ? `<p class="error">${escapeHtml(message)}</p>` : ''}
<form action="/login/mfa" method="post">${csrfField(req)}
<label>Code <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></label>
<button type="submit">Check code</button></form>`,
    );

  app.get('/login/mfa', (req, res) => {
    res.type('html').send(mfaPage(req));
  });

  app.post('/login/mfa', (req, res) => {
    if (validate(req, res, ['_csrf', 'code'], ['code'])) return;
    const pending = req.session.pendingUserId;
    if (!pending) return sendError(req, res, 403, 'forbidden');
    if (limiterExceeded('mfa', pending)) {
      record(req, 'ratelimit.hit', 'blocked', { bucket: 'mfa' });
      res.setHeader('Retry-After', '900');
      return sendError(req, res, 429, 'too_many_requests');
    }
    if (!verifyTotp(totpSeed, req.body.code)) {
      const over = limiterHit('mfa', pending);
      record(req, 'auth.mfa.failure', 'failure', {});
      if (over) {
        record(req, 'ratelimit.hit', 'blocked', { bucket: 'mfa' });
        res.setHeader('Retry-After', '900');
        return sendError(req, res, 429, 'too_many_requests');
      }
      return res.status(401).type('html').send(mfaPage(req, 'That code is not correct.'));
    }
    rotateSession(req, res, { userId: pending, pendingUserId: null });
    record(req, 'auth.login.success', 'success', { factor: 'password+totp' });
    return res.redirect(303, '/account');
  });

  app.get('/forgot-password', (req, res) => {
    res.type('html').send(
      layout(
        req,
        'Reset your password',
        `<h1>Reset your password</h1><form action="/forgot-password" method="post">${csrfField(req)}
<label>Email <input type="email" name="email" autocomplete="username"></label>
<button type="submit">Send a reset link</button></form>`,
      ),
    );
  });

  app.post('/forgot-password', (req, res) => {
    if (validate(req, res, ['_csrf', 'email'], ['email'])) return;
    const email = String(req.body.email ?? '').toLowerCase();
    if (limiterExceeded('reset', email) || limiterHit('reset', email)) {
      record(req, 'ratelimit.hit', 'blocked', { bucket: 'reset' });
      res.setHeader('Retry-After', '3600');
      return sendError(req, res, 429, 'too_many_requests');
    }
    record(req, 'auth.password.reset.requested', 'success', {});
    // The same answer whether or not the account exists.
    return res.redirect(303, '/login');
  });

  // --- signed-in routes --------------------------------------------------------------------------

  app.post('/logout', (req, res) => {
    if (requireAuth(req, res)) return;
    sessions.delete(req.session.id);
    record(req, 'auth.logout', 'success', {});
    clearSessionCookie(res);
    res.setHeader('Clear-Site-Data', '"cookies", "storage"');
    res.redirect(303, '/login');
  });

  app.get('/account', (req, res) => {
    if (requireAuth(req, res)) return;
    const user = userOf(req.session);
    res
      .type('html')
      .send(layout(req, 'Your account', `<h1>Your account</h1><p>Signed in as ${escapeHtml(user?.email ?? '')} (${escapeHtml(user?.role ?? '')}).</p>`));
  });

  app.get('/notes', (req, res) => {
    if (requireAuth(req, res)) return;
    const user = userOf(req.session);
    const items = notes
      .filter((n) => n.owner_id === user?.id)
      .map((n) => `<li><a href="/notes/${escapeHtml(n.id)}">${escapeHtml(n.title)}</a> — ${escapeHtml(n.body)}</li>`)
      .join('');
    res.type('html').send(layout(req, 'Your notes', `<h1>Your notes</h1><ul>${items}</ul>`));
  });

  app.get('/notes/:id', (req, res) => {
    if (requireAuth(req, res)) return;
    const note = ownedNote(req, res);
    if (!note) return;
    res.type('html').send(layout(req, 'Note', `<h1>${escapeHtml(note.title)}</h1><p>${escapeHtml(note.body)}</p>`));
  });

  app.post('/notes/:id/delete', (req, res) => {
    if (requireAuth(req, res)) return;
    const note = ownedNote(req, res);
    if (!note) return;
    notes.splice(notes.indexOf(note), 1);
    res.redirect(303, '/notes');
  });

  app.get('/admin', (req, res) => {
    if (requireRole(req, res, ADMIN_ROLE)) return;
    res.type('html').send(layout(req, 'Administration', `<h1>Administration</h1><p>${notes.length} notes, ${users.length} accounts.</p>`));
  });

  // --- JSON API ----------------------------------------------------------------------------------

  app.get('/api/notes', (req, res) => {
    if (requireAuth(req, res)) return;
    const user = userOf(req.session);
    res.json({ notes: notes.filter((n) => n.owner_id === user?.id).map((n) => ({ id: n.id, title: n.title, body: n.body })) });
  });

  app.post('/api/notes', (req, res) => {
    if (requireAuth(req, res)) return;
    if (!/application\/json/i.test(req.get('content-type') ?? '')) return sendError(req, res, 415, 'unsupported_media_type');
    if (validate(req, res, ['title', 'body'], ['title'])) return;
    const key = req.get('idempotency-key');
    if (key && idempotency.has(key)) {
      res.setHeader('Idempotent-Replayed', 'true');
      return res.status(201).json(idempotency.get(key));
    }
    const user = userOf(req.session);
    const note = { id: crypto.randomUUID(), owner_id: user.id, title: String(req.body.title), body: String(req.body.body ?? '') };
    notes.push(note);
    const payload = { id: note.id, title: note.title, body: note.body };
    if (key) idempotency.set(key, payload);
    return res.status(201).json(payload);
  });

  app.get('/api/notes/:id', (req, res) => {
    if (requireAuth(req, res)) return;
    const note = ownedNote(req, res);
    if (!note) return;
    res.json({ id: note.id, title: note.title, body: note.body });
  });

  // --- 405 / 404 / errors ------------------------------------------------------------------------

  app.use((req, res, next) => {
    if (findRoute(req.method === 'HEAD' ? 'GET' : req.method, req.path)) return next();
    const allowed = methodsForPath(req.path);
    if (allowed.length > 0) {
      res.setHeader('Allow', allowed.join(', '));
      return sendError(req, res, 405, 'method_not_allowed');
    }
    return sendError(req, res, 404, 'not_found');
  });

  app.use((req, res) => sendError(req, res, 404, 'not_found'));

  // The last handler never shows technical detail: a generic message, the detail stays in the log.
  app.use((err, req, res, _next) => {
    const status =
      err.type === 'entity.too.large' ? 413 : Number(err.status ?? err.statusCode ?? 0) || (err instanceof URIError ? 400 : 500);
    if (status >= 500) record(req, 'error.unhandled', 'failure', { reqId: req.reqId });
    if (res.headersSent) {
      res.end();
      return;
    }
    sendError(req, res, status);
  });

  app.locals.securevibeFixture = { testMode, tlsMode, seededNoteId, users, notes, events };
  return app;
}
