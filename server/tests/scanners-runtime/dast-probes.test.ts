/**
 * The runtime probes end to end against the fixture app (server/tests/fixtures/scanners-runtime/mini-app),
 * which implements the CONTRACTS §1.16 test-bootstrap contract.
 *
 * The app runs inside this process over a pair of linked streams that stand in for a TCP connection, so the
 * probes talk real HTTP without a listening socket (see helpers/loopback.ts and the note in
 * dast-harness.test.ts about the spawn-and-listen path).
 */
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runProbes } from '../../src/scanners/dast/runner.js';
import type { ProbeContext, ProbeResult } from '../../src/scanners/dast/types.js';
import { ALL_PROBES } from '../../src/scanners/dast/probes/index.js';
import { authMfaRateLimited } from '../../src/scanners/dast/probes/rate.js';
import { base32Encode, totp } from '../../src/scanners/dast/totp.js';
import { startMiniApp, type MiniAppHandle } from './helpers/mini-app.js';

function byId(results: ProbeResult[]): Map<string, ProbeResult> {
  return new Map(results.map((r) => [r.id, r]));
}

function describeResult(r: ProbeResult | undefined): string {
  if (!r) return 'the probe did not run at all';
  return `${r.id}: passed=${String(r.passed)} observed="${r.observed}" reason="${r.reason ?? ''}"`;
}

describe('runtime probes against the fixture app (test mode)', () => {
  let handle: MiniAppHandle;
  let ctx: ProbeContext;
  let results: Map<string, ProbeResult>;

  beforeAll(async () => {
    handle = await startMiniApp({ phase: 'test' });
    ctx = handle.ctx;
    results = byId(await runProbes(ctx));
  }, 120_000);

  afterAll(() => handle?.close());

  it('signs in every seeded account, including the administrator with a one-time code', () => {
    expect(handle.signInFailures).toEqual([]);
    expect([...ctx.sessions.keys()].sort()).toEqual(['admin', 'member', 'member2', 'staff']);
    expect(ctx.sessions.get('admin')?.role).toBe('admin');
  });

  it('reads the route registry export', () => {
    expect(ctx.routes?.routes.length).toBeGreaterThan(10);
    expect(ctx.routes?.entities[0]?.name).toBe('note');
    expect(ctx.routes?.entities[0]?.sample.id).toBeTruthy();
  });

  it('runs every test-phase probe exactly once, in group order', () => {
    const expected = ALL_PROBES.filter((p) => (p.phase ?? 'test') === 'test').map((p) => p.id);
    expect([...results.keys()].sort()).toEqual([...expected].sort());
    const groups = [...results.values()].map((r) => r.group);
    const firstIndex = new Map<string, number>();
    groups.forEach((g, i) => {
      if (!firstIndex.has(g)) firstIndex.set(g, i);
    });
    // `rate` probes are deliberately last because they exhaust the limiter budgets.
    expect([...firstIndex.keys()].pop()).toBe('rate');
  });

  it('never marks a probe that could not run as passed', () => {
    for (const r of results.values()) {
      if (r.passed === null) expect(r.reason, describeResult(r)).toBeTruthy();
      expect([true, false, null]).toContain(r.passed);
    }
  });

  it.each([
    'dast.headers.csp',
    'dast.headers.nosniff',
    'dast.headers.referrer-policy',
    'dast.headers.content-type-charset',
    'dast.cors.origin-not-reflected',
    'dast.cache.no-store-authenticated',
    'dast.cookie.session-attributes',
  ])('passes the header probe %s', (id) => {
    expect(describeResult(results.get(id))).toContain('passed=true');
  });

  it.each(['dast.csrf.missing-token-rejected', 'dast.csrf.cross-origin-rejected', 'dast.csrf.get-does-not-mutate'])(
    'passes the cross-site request forgery probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.authz.anonymous-denied', 'dast.authz.wrong-role-denied', 'dast.authz.non-owner-denied', 'dast.authz.unregistered-route'])(
    'passes the authorization probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.session.rotated-on-login', 'dast.session.reuse-after-logout-denied', 'dast.session.id-format', 'dast.session.logout-visible', 'dast.session.logout-clear-site-data'])(
    'passes the session probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.errors.no-stack-trace', 'dast.errors.404-generic', 'dast.errors.method-not-allowed'])(
    'passes the error-handling probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.leak.dotfiles', 'dast.leak.directory-listing', 'dast.leak.trace', 'dast.leak.health-minimal', 'dast.health.healthz'])(
    'passes the information-leak probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.input.oversized-body', 'dast.input.duplicate-param', 'dast.input.proto-pollution', 'dast.input.unknown-field', 'dast.input.type-confusion', 'dast.input.sql-smoke', 'dast.input.path-traversal-smoke'])(
    'passes the input-handling probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.log.login-failure-logged', 'dast.log.authz-denial-logged', 'dast.log.validation-rejected-logged'])(
    'passes the log-evidence probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it.each(['dast.xss.reflected-smoke', 'dast.xss.stored-smoke', 'dast.redirect.open-redirect-blocked', 'dast.api.json-content-type', 'dast.api.idempotency-key'])(
    'passes the probe %s',
    (id) => {
      expect(describeResult(results.get(id))).toContain('passed=true');
    },
  );

  it('finds the sign-in rate limit and ignores a forged X-Forwarded-For header', () => {
    expect(describeResult(results.get('dast.auth.login-rate-limited'))).toContain('passed=true');
    expect(describeResult(results.get('dast.rate.xff-spoof-ignored'))).toContain('passed=true');
    expect(results.get('dast.auth.login-rate-limited')?.observed).toMatch(/429/);
  });

  it('finds the one-time-code and password-reset rate limits', () => {
    expect(describeResult(results.get('dast.auth.mfa-rate-limited'))).toContain('passed=true');
    expect(describeResult(results.get('dast.rate.reset-limited'))).toContain('passed=true');
  });

  it('records a reason instead of a pass when the endpoint does not exist', () => {
    // The fixture app has no sign-up form, so these three probes must record why they could not run.
    const registration = results.get('dast.rate.registration-limited');
    expect(registration?.passed).toBeNull();
    expect(registration?.reason).toMatch(/sign-up/i);

    const weakPassword = results.get('dast.auth.weak-password-rejected');
    expect(weakPassword?.passed).toBeNull();
    expect(weakPassword?.reason).toMatch(/registration or change-password/i);

    // Uploads and the AI assistant are switched off in this build, so their probes must not claim a pass.
    for (const id of ['dast.upload.oversize-413', 'dast.ai.injection-blocked-and-logged', 'dast.apikey.query-string-rejected']) {
      expect(results.get(id)?.passed, id).toBeNull();
      expect(results.get(id)?.reason, id).toBeTruthy();
    }
  });

  it('keeps administrator pages closed until the one-time code is entered', () => {
    expect(describeResult(results.get('dast.auth.admin-mfa-enforced'))).toContain('passed=true');
  });

  it('carries request and response excerpts on the probes that made a request', () => {
    const csp = results.get('dast.headers.csp');
    expect(csp?.requestExcerpt).toContain('GET ');
    expect(csp?.responseExcerpt).toContain('content-security-policy');
    // Cookies and tokens are redacted in the excerpts that end up in the report.
    expect(csp?.responseExcerpt).not.toMatch(/sid=[A-Za-z0-9_-]{20,}/);
  });
});

describe('the one-time-code rate probe with an unlucky seed', () => {
  it('never submits the live code as one of its wrong guesses', async () => {
    // The probe guesses 100001, 100002, ...; pick a seed whose accepted codes include one of those guesses.
    let seed: string;
    do {
      seed = base32Encode(randomBytes(20));
    } while (![0, 1].some((offset) => /^1000(0[1-9]|1[01])$/.test(totp(seed, { offset }))));
    const handle = await startMiniApp({ phase: 'test', extraEnv: { SECUREVIBE_TEST_TOTP_SEED: seed } });
    try {
      const [result] = await runProbes(handle.ctx, { probes: [authMfaRateLimited] });
      expect(describeResult(result)).toContain('passed=true');
    } finally {
      handle.close();
    }
  }, 60_000);
});
