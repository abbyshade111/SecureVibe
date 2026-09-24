/**
 * Header probes: CSP, HSTS, nosniff and the other policy headers, charset, CORS, caching, session cookie
 * attributes (test phase and the pretend-TLS-proxy production phase) and the TLS minimum version.
 */
import tls from 'node:tls';
import { isSessionSetCookie, parseSetCookie, type HttpResponse } from '../http.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule, type ProbeOutcome } from '../types.js';
import { fail, pass } from './util.js';

const REQUIRED_CSP: { directive: string; must: RegExp; describe: string }[] = [
  { directive: 'default-src', must: /^'self'$/, describe: "default-src 'self'" },
  { directive: 'script-src', must: /'nonce-[^']+'.*'strict-dynamic'|'strict-dynamic'.*'nonce-[^']+'/, describe: "script-src 'nonce-…' 'strict-dynamic'" },
  { directive: 'object-src', must: /'none'/, describe: "object-src 'none'" },
  { directive: 'base-uri', must: /'none'/, describe: "base-uri 'none'" },
  { directive: 'frame-ancestors', must: /'none'/, describe: "frame-ancestors 'none'" },
  { directive: 'form-action', must: /'self'/, describe: "form-action 'self'" },
];

export function parseCsp(header: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const [name, ...values] = trimmed.split(/\s+/);
    out.set((name ?? '').toLowerCase(), values.join(' '));
  }
  return out;
}

export function cspProblems(header: string | undefined): string[] {
  if (!header) return ['no Content-Security-Policy header'];
  const csp = parseCsp(header);
  const problems: string[] = [];
  for (const rule of REQUIRED_CSP) {
    const value = csp.get(rule.directive);
    if (value === undefined) problems.push(`missing ${rule.directive}`);
    else if (!rule.must.test(value)) problems.push(`${rule.directive} is "${value}" (expected ${rule.describe})`);
  }
  const script = csp.get('script-src') ?? '';
  if (/'unsafe-inline'|'unsafe-eval'/.test(script)) problems.push("script-src allows 'unsafe-inline' or 'unsafe-eval'");
  if (/\*|https?:/.test(script) && !/'strict-dynamic'/.test(script)) problems.push('script-src allows any external origin');
  return problems;
}

async function loginOrHome(ctx: ProbeContext): Promise<HttpResponse> {
  const login = await ctx.http.get(ctx.paths.login);
  if (login.status === 200 && /text\/html/.test(login.contentType())) return login;
  return ctx.http.get('/');
}

export const headersCsp: ProbeModule = {
  id: 'dast.headers.csp',
  group: 'headers',
  requirementIds: ['V3.4.3', 'V3.4.6'],
  fallback: {
    title: 'Content Security Policy missing or weakened',
    severity: 'high',
    cwe: ['CWE-693', 'CWE-79'],
    description: 'A page did not carry the expected Content-Security-Policy header (nonce-based script-src, object-src none, base-uri none, frame-ancestors none).',
    impact: 'Without this policy the browser runs any script that gets injected into a page, so one escaping mistake becomes account takeover.',
    fix: "Restore the template's CSP in src/security/headers.ts and remove any code that overrides it.",
  },
  async run(ctx) {
    const expected = "Content-Security-Policy with default-src 'self', script-src 'nonce-…' 'strict-dynamic', object-src 'none', base-uri 'none', frame-ancestors 'none', form-action 'self'";
    const res = await loginOrHome(ctx);
    const problems = cspProblems(res.header('content-security-policy'));
    if (problems.length === 0) return pass(expected, 'policy present with every required directive', res);
    return fail(expected, problems.join('; '), res);
  },
};

export const headersHsts: ProbeModule = {
  id: 'dast.headers.hsts',
  group: 'headers',
  phase: 'production',
  requirementIds: ['V3.4.1'],
  fallback: {
    title: 'HTTP Strict Transport Security header missing behind TLS',
    severity: 'medium',
    cwe: ['CWE-319'],
    description: 'When the app runs behind a TLS proxy it did not send Strict-Transport-Security with a max-age of at least one year.',
    impact: 'Browsers may still be tricked into using plain HTTP for a first visit, exposing the session cookie.',
    fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains whenever TLS_MODE is not off.',
  },
  async run(ctx) {
    const expected = 'Strict-Transport-Security: max-age=31536000; includeSubDomains when TLS_MODE=proxy and X-Forwarded-Proto: https';
    const res = await ctx.http.get('/', { headers: { 'X-Forwarded-Proto': 'https' } });
    const hsts = res.header('strict-transport-security');
    if (!hsts) return fail(expected, 'no Strict-Transport-Security header', res);
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (maxAge < 31_536_000) return fail(expected, `max-age is ${maxAge} (less than one year)`, res);
    if (!/includesubdomains/i.test(hsts)) return fail(expected, `includeSubDomains missing: ${hsts}`, res);
    return pass(expected, hsts, res);
  },
};

export const headersNosniff: ProbeModule = {
  id: 'dast.headers.nosniff',
  group: 'headers',
  requirementIds: ['V3.4.4'],
  fallback: {
    title: 'X-Content-Type-Options: nosniff missing',
    severity: 'low',
    cwe: ['CWE-693'],
    description: 'A response did not tell the browser to trust the declared content type.',
    impact: 'Browsers may guess a different type and run a file as script, which helps some injection attacks.',
    fix: 'Keep helmet enabled so every response carries X-Content-Type-Options: nosniff.',
  },
  async run(ctx) {
    const expected = 'X-Content-Type-Options: nosniff on pages, API responses and error responses';
    const responses = await Promise.all([ctx.http.get('/'), ctx.http.get('/healthz'), ctx.http.get('/no-such-page-securevibe')]);
    for (const res of responses) {
      if ((res.header('x-content-type-options') ?? '').toLowerCase() !== 'nosniff') return fail(expected, `missing on ${res.request.path} (status ${res.status})`, res);
    }
    return pass(expected, 'present on every response checked', responses[0]);
  },
};

export const headersReferrerPolicy: ProbeModule = {
  id: 'dast.headers.referrer-policy',
  group: 'headers',
  requirementIds: ['V3.4.5'],
  fallback: {
    title: 'Policy headers missing (Referrer-Policy, Permissions-Policy, framing, cross-origin isolation)',
    severity: 'low',
    cwe: ['CWE-693'],
    description: 'A page did not carry one of the browser policy headers: Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy or X-Frame-Options.',
    impact: 'Missing policies let other sites learn URLs, embed the app in frames, or open it with shared browsing context.',
    fix: "Keep helmet with the template's settings and set Permissions-Policy: camera=(), microphone=(), geolocation=().",
  },
  async run(ctx) {
    const expected = 'Referrer-Policy: strict-origin-when-cross-origin; Permissions-Policy; Cross-Origin-Opener-Policy: same-origin; Cross-Origin-Resource-Policy: same-origin; X-Frame-Options: DENY';
    const res = await loginOrHome(ctx);
    const problems: string[] = [];
    const referrer = (res.header('referrer-policy') ?? '').toLowerCase();
    if (!/strict-origin-when-cross-origin|no-referrer|same-origin/.test(referrer)) problems.push(`Referrer-Policy is "${referrer || 'missing'}"`);
    if (!res.header('permissions-policy')) problems.push('Permissions-Policy missing');
    if ((res.header('cross-origin-opener-policy') ?? '').toLowerCase() !== 'same-origin') problems.push('Cross-Origin-Opener-Policy is not same-origin');
    if ((res.header('cross-origin-resource-policy') ?? '').toLowerCase() !== 'same-origin') problems.push('Cross-Origin-Resource-Policy is not same-origin');
    if (!/deny|sameorigin/i.test(res.header('x-frame-options') ?? '')) problems.push('X-Frame-Options missing');
    return problems.length === 0 ? pass(expected, 'all policy headers present', res) : fail(expected, problems.join('; '), res);
  },
};

export const headersContentTypeCharset: ProbeModule = {
  id: 'dast.headers.content-type-charset',
  group: 'headers',
  requirementIds: ['V4.1.1'],
  fallback: {
    title: 'Content-Type without charset',
    severity: 'low',
    cwe: ['CWE-436'],
    description: 'A text response did not declare charset=utf-8 in its Content-Type header.',
    impact: 'Browsers may guess the encoding, which enables some cross-site scripting tricks with unusual encodings.',
    fix: 'Always send Content-Type with charset=utf-8 (res.type("html") and res.json do this in the template).',
  },
  async run(ctx) {
    const expected = 'every text/HTML/JSON response carries Content-Type with charset=utf-8';
    const responses = await Promise.all([ctx.http.get('/'), ctx.http.get(ctx.paths.login), ctx.http.get('/healthz'), ctx.http.get('/no-such-page-securevibe'), ctx.http.get('/api/no-such-endpoint-securevibe')]);
    for (const res of responses) {
      if (!res.body) continue;
      const type = res.contentType().toLowerCase();
      if (!/^(text\/|application\/json|application\/javascript)/.test(type)) continue;
      if (!/charset=utf-8/.test(type)) return fail(expected, `${res.request.path} (status ${res.status}) sent "${type || 'no Content-Type'}"`, res);
    }
    return pass(expected, 'charset declared on every text response checked', responses[0]);
  },
};

export const corsOriginNotReflected: ProbeModule = {
  id: 'dast.cors.origin-not-reflected',
  group: 'headers',
  requirementIds: ['V3.4.2'],
  fallback: {
    title: 'Cross-origin requests are allowed (Origin reflected)',
    severity: 'high',
    cwe: ['CWE-942'],
    description: 'The app answered a request from another website with Access-Control-Allow-Origin, so browsers would let that site read the response.',
    impact: 'A malicious page could read a signed-in user’s data through the browser.',
    fix: 'Remove any CORS middleware; the app is meant to be used from its own pages only.',
  },
  async run(ctx) {
    const expected = 'no Access-Control-Allow-Origin header for a foreign Origin (GET and preflight)';
    const evil = 'https://evil.example';
    const get = await ctx.http.get('/', { headers: { Origin: evil } });
    const preflight = await ctx.http.request('/', {
      method: 'OPTIONS',
      sameOrigin: false,
      headers: { Origin: evil, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' },
    });
    for (const res of [get, preflight]) {
      const acao = res.header('access-control-allow-origin');
      if (acao && (acao === '*' || acao === evil)) return fail(expected, `${res.request.method} answered Access-Control-Allow-Origin: ${acao}`, res);
    }
    return pass(expected, 'no CORS headers for a foreign origin', get);
  },
};

export const cacheNoStoreAuthenticated: ProbeModule = {
  id: 'dast.cache.no-store-authenticated',
  group: 'headers',
  requirementIds: ['V14.3.2'],
  fallback: {
    title: 'Signed-in pages may be cached',
    severity: 'medium',
    cwe: ['CWE-525'],
    description: 'A page shown to a signed-in user did not carry Cache-Control: no-store.',
    impact: 'On a shared computer the next person could see the page from the browser cache after sign-out.',
    fix: 'Send Cache-Control: no-store, private on every authenticated response (authenticatedCacheControl in the template).',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member') ?? ctx.sessions.get('staff') ?? ctx.sessions.get('admin');
    if (!session) return NOT_ATTEMPTED('no signed-in session was available');
    const path = ctx.pageFor('user') ?? ctx.paths.account;
    const expected = `Cache-Control: no-store on ${path} for a signed-in user`;
    const res = await ctx.http.get(path, { jar: session.jar });
    if (res.status !== 200) return NOT_ATTEMPTED(`${path} answered ${res.status} for a signed-in user`, expected);
    const cache = (res.header('cache-control') ?? '').toLowerCase();
    return /no-store/.test(cache) ? pass(expected, `Cache-Control: ${cache}`, res) : fail(expected, `Cache-Control: ${cache || 'missing'}`, res);
  },
};

function sessionCookieLines(res: HttpResponse): string[] {
  return res.setCookies.filter((c) => isSessionSetCookie(c));
}

export const cookieSessionAttributes: ProbeModule = {
  id: 'dast.cookie.session-attributes',
  group: 'headers',
  requirementIds: ['V3.3.2', 'V3.3.4'],
  fallback: {
    title: 'Session cookie without HttpOnly or SameSite=Strict',
    severity: 'high',
    cwe: ['CWE-1004', 'CWE-1275'],
    description: 'The session cookie was set without HttpOnly, SameSite=Strict or Path=/.',
    impact: 'Scripts could read the session id, or other sites could send requests with the user’s session.',
    fix: 'Set the session cookie with HttpOnly; SameSite=Strict; Path=/ (and Secure in TLS modes).',
  },
  async run(ctx) {
    const expected = 'session cookie sid with HttpOnly; SameSite=Strict; Path=/';
    const page = await ctx.http.get(ctx.paths.login);
    let lines = sessionCookieLines(page);
    let observedOn: HttpResponse = page;
    if (lines.length === 0) {
      const attempt = await ctx.loginAttempt('nobody@test.local', 'not-the-password-123456');
      lines = sessionCookieLines(attempt);
      observedOn = attempt;
    }
    const seeded = ctx.seededUsers[0];
    if (lines.length === 0 && seeded && ctx.secrets.password) {
      // Apps that only issue a session on a successful sign-in.
      const signedIn = await ctx.loginAttempt(seeded.email, ctx.secrets.password);
      lines = sessionCookieLines(signedIn);
      observedOn = signedIn;
    }
    if (lines.length === 0) return NOT_ATTEMPTED('no session cookie was set on the sign-in page or a sign-in attempt', expected);
    const cookie = parseSetCookie(lines[0] ?? '');
    const problems: string[] = [];
    if (!('httponly' in cookie.attrs)) problems.push('HttpOnly missing');
    if ((cookie.attrs['samesite'] ?? '').toLowerCase() !== 'strict') problems.push(`SameSite is ${cookie.attrs['samesite'] ?? 'missing'}`);
    if ((cookie.attrs['path'] ?? '') !== '/') problems.push(`Path is ${cookie.attrs['path'] ?? 'missing'}`);
    if ('domain' in cookie.attrs) problems.push('Domain attribute present');
    return problems.length === 0 ? pass(expected, `${cookie.name} set with HttpOnly, SameSite=Strict, Path=/`, observedOn) : fail(expected, problems.join('; '), observedOn);
  },
};

export const cookieSecureHostPrefix: ProbeModule = {
  id: 'dast.cookie.secure-host-prefix',
  group: 'headers',
  phase: 'production',
  requirementIds: ['V3.3.1', 'V3.3.3'],
  fallback: {
    title: 'Session cookie not Secure / not __Host- prefixed behind TLS',
    severity: 'high',
    cwe: ['CWE-614'],
    description: 'Behind a TLS proxy the session cookie was not named __Host-sid with the Secure flag.',
    impact: 'The session id could travel over plain HTTP or be overwritten from a subdomain.',
    fix: 'In TLS modes name the cookie __Host-sid and set Secure; Path=/ without a Domain attribute.',
  },
  async run(ctx) {
    const expected = '__Host-sid cookie with Secure; HttpOnly; SameSite=Strict; Path=/ and no Domain when TLS_MODE=proxy';
    const res = await ctx.http.get(ctx.paths.login, { headers: { 'X-Forwarded-Proto': 'https' } });
    const lines = res.setCookies.filter((c) => isSessionSetCookie(c));
    if (lines.length === 0) return NOT_ATTEMPTED('no session cookie was set on the sign-in page in production mode', expected);
    const cookie = parseSetCookie(lines[0] ?? '');
    const problems: string[] = [];
    if (cookie.name !== '__Host-sid') problems.push(`cookie is named ${cookie.name}`);
    if (!('secure' in cookie.attrs)) problems.push('Secure missing');
    if (!('httponly' in cookie.attrs)) problems.push('HttpOnly missing');
    if ('domain' in cookie.attrs) problems.push('Domain attribute present');
    return problems.length === 0 ? pass(expected, '__Host-sid set with Secure', res) : fail(expected, problems.join('; '), res);
  },
};

export const tlsMinVersion: ProbeModule = {
  id: 'dast.tls.min-version',
  group: 'headers',
  phase: 'selfsigned',
  requirementIds: ['V12.1.1', 'V12.1.2'],
  fallback: {
    title: 'Old TLS versions accepted',
    severity: 'medium',
    cwe: ['CWE-326'],
    description: 'The self-signed TLS listener accepted a TLS 1.1 or older connection.',
    impact: 'Old protocol versions have known weaknesses that let attackers read or alter traffic.',
    fix: 'Set minVersion: TLSv1.2 and a modern cipher list on the HTTPS server.',
  },
  async run(ctx) {
    const expected = 'TLS 1.2 or newer only (a TLS 1.1 handshake is refused)';
    const connectWith = (max: tls.SecureVersion): Promise<{ ok: boolean; protocol?: string; error?: string }> =>
      new Promise((resolveConn) => {
        // This probe tests which TLS versions the local app accepts, not whether its self-signed certificate chains.
        const socket = tls.connect({ host: '127.0.0.1', port: ctx.app.port, rejectUnauthorized: false, minVersion: 'TLSv1', maxVersion: max, timeout: 5_000 }, () => {
          resolveConn({ ok: true, protocol: socket.getProtocol() ?? undefined });
          socket.destroy();
        });
        socket.on('error', (err) => resolveConn({ ok: false, error: err.message }));
        socket.on('timeout', () => {
          socket.destroy();
          resolveConn({ ok: false, error: 'timeout' });
        });
      });
    const old = await connectWith('TLSv1.1');
    const modern = await connectWith('TLSv1.3');
    if (!modern.ok) return NOT_ATTEMPTED(`a modern TLS connection failed: ${modern.error ?? 'unknown'}`, expected);
    const outcome: ProbeOutcome = old.ok
      ? { passed: false, expected, observed: `TLS 1.1 handshake succeeded (${old.protocol ?? ''})`, endpoint: 'TLS handshake' }
      : { passed: true, expected, observed: `TLS 1.1 refused (${old.error ?? 'handshake failed'}); ${modern.protocol ?? 'modern TLS'} accepted`, endpoint: 'TLS handshake' };
    return outcome;
  },
};

export const headerProbes: ProbeModule[] = [
  headersCsp,
  headersNosniff,
  headersReferrerPolicy,
  headersContentTypeCharset,
  corsOriginNotReflected,
  cacheNoStoreAuthenticated,
  cookieSessionAttributes,
  headersHsts,
  cookieSecureHostPrefix,
  tlsMinVersion,
];
