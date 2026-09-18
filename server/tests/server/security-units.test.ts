/**
 * Unit-level coverage of the security primitives that does not need a bound socket (this sandbox's Bash tool
 * refuses any `listen()`, including on 127.0.0.1 — see security.test.ts's header comment). These exercise the
 * exact logic the HTTP-level tests in security.test.ts drive through supertest, just called directly.
 */
import { describe, expect, it } from 'vitest';
import { isAllowedHost, isAllowedOrigin, originCheck, splitHost } from '../../src/security/middleware.js';
import { clearSessionCookieHeader, parseCookies, sessionCookieHeader, SessionManager } from '../../src/security/token.js';
import { HttpError } from '../../src/security/errors.js';

describe('host allow-list', () => {
  it('accepts 127.0.0.1, localhost and [::1]', () => {
    expect(isAllowedHost('127.0.0.1:4173', { port: 4173 })).toBe(true);
    expect(isAllowedHost('localhost:4173', { port: 4173 })).toBe(true);
    expect(isAllowedHost('[::1]:4173', { port: 4173 })).toBe(true);
  });

  it('rejects a different host, and a right host with the wrong port', () => {
    expect(isAllowedHost('evil.example.com', { port: 4173 })).toBe(false);
    expect(isAllowedHost('127.0.0.1:9999', { port: 4173 })).toBe(false);
  });

  it('splits host and port', () => {
    expect(splitHost('127.0.0.1:4173')).toEqual({ hostname: '127.0.0.1', port: 4173 });
    expect(splitHost('localhost')).toEqual({ hostname: 'localhost' });
  });
});

describe('origin allow-list', () => {
  it('accepts a same-origin http Origin', () => {
    expect(isAllowedOrigin('http://127.0.0.1:4173', { port: 4173 })).toBe(true);
  });

  it('rejects a cross-site Origin and https (SecureVibe only ever speaks http to itself)', () => {
    expect(isAllowedOrigin('https://127.0.0.1:4173', { port: 4173 })).toBe(false);
    expect(isAllowedOrigin('http://evil.example.com', { port: 4173 })).toBe(false);
  });
});

function fakeReq(overrides: Partial<{ method: string; headers: Record<string, string> }>) {
  const headers = overrides.headers ?? {};
  return {
    method: overrides.method ?? 'POST',
    header: (name: string) => headers[name.toLowerCase()],
  } as never;
}

describe('originCheck middleware', () => {
  const middleware = originCheck({ port: 4173 });

  it('passes GET through untouched', () => {
    let nextArg: unknown = 'not-called';
    middleware(fakeReq({ method: 'GET' }), {} as never, (err?: unknown) => (nextArg = err));
    expect(nextArg).toBeUndefined();
  });

  it('blocks a mutating request with a cross-site Origin', () => {
    let nextArg: unknown;
    middleware(fakeReq({ method: 'POST', headers: { origin: 'https://evil.example.com' } }), {} as never, (err?: unknown) => (nextArg = err));
    expect(nextArg).toBeInstanceOf(HttpError);
  });

  it('blocks an opaque ("null") Origin on a mutating request', () => {
    let nextArg: unknown;
    middleware(fakeReq({ method: 'POST', headers: { origin: 'null' } }), {} as never, (err?: unknown) => (nextArg = err));
    expect(nextArg).toBeInstanceOf(HttpError);
  });

  it('allows a same-origin mutating request with no Origin header (typed URL) and same-origin Sec-Fetch-Site', () => {
    let nextArg: unknown = 'not-called';
    middleware(fakeReq({ method: 'PUT', headers: { 'sec-fetch-site': 'same-origin' } }), {} as never, (err?: unknown) => (nextArg = err));
    expect(nextArg).toBeUndefined();
  });

  it('blocks a mutating request whose Sec-Fetch-Site says cross-site', () => {
    let nextArg: unknown;
    middleware(fakeReq({ method: 'POST', headers: { 'sec-fetch-site': 'cross-site' } }), {} as never, (err?: unknown) => (nextArg = err));
    expect(nextArg).toBeInstanceOf(HttpError);
  });
});

describe('SessionManager', () => {
  it('exchanges the startup token for the life of the process and rejects a wrong token', () => {
    const sessions = new SessionManager({ token: 'abc123' });
    expect(sessions.exchange('wrong')).toBeUndefined();
    const session = sessions.exchange('abc123');
    expect(session).toBeDefined();
    expect(sessions.tokenAlreadyUsed).toBe(true);
    // A browser prefetch must not lock the owner out: the same link still works, and each exchange is its own session.
    const second = sessions.exchange('abc123');
    expect(second).toBeDefined();
    expect(second!.id).not.toBe(session!.id);
  });

  it('validates a session by cookie value and expires it after the idle window', () => {
    let now = 1_000_000;
    const sessions = new SessionManager({ token: 'abc123', idleMs: 1000, now: () => now });
    const session = sessions.exchange('abc123')!;
    expect(sessions.validate(session.id)).toBeDefined();
    now += 1500;
    expect(sessions.validate(session.id)).toBeUndefined();
  });

  it('matches the CSRF token only for the right session and value', () => {
    const sessions = new SessionManager({ token: 'abc123' });
    const session = sessions.exchange('abc123')!;
    const other = sessions.createSession();
    expect(sessions.csrfMatches(session, session.csrfToken)).toBe(true);
    expect(sessions.csrfMatches(session, other.csrfToken)).toBe(false);
    expect(sessions.csrfMatches(session, undefined)).toBe(false);
  });

  it('revokes a session', () => {
    const sessions = new SessionManager({ token: 'abc123' });
    const session = sessions.exchange('abc123')!;
    sessions.revoke(session.id);
    expect(sessions.validate(session.id)).toBeUndefined();
  });
});

describe('cookies', () => {
  it('builds an HttpOnly, SameSite=Strict session cookie and a matching clear header', () => {
    const set = sessionCookieHeader('abc');
    expect(set).toMatch(/^securevibe_session=abc; Path=\/; HttpOnly; SameSite=Strict$/);
    expect(clearSessionCookieHeader()).toMatch(/Max-Age=0/);
  });

  it('parses a Cookie header', () => {
    expect(parseCookies('a=1; b=hello%20world')).toEqual({ a: '1', b: 'hello world' });
    expect(parseCookies(undefined)).toEqual({});
  });
});
