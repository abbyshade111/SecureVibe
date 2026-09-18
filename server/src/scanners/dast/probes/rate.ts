/**
 * Anti-automation probes (CONTRACTS §1.8). These run last because they deliberately exhaust limiter budgets;
 * the runner resets the limiters between them through POST /__securevibe/reset-rate-limits.
 */
import { CookieJar, extractCsrfToken } from '../http.js';
import { totp } from '../totp.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule, type ProbeOutcome } from '../types.js';
import { fail, pass } from './util.js';

/** How many attempts a probe makes before deciding a limiter is missing (presets allow 3-20 in a window). */
const MAX_ATTEMPTS = 30;

function retryAfterNote(header: string | undefined): string {
  return header ? ` with Retry-After: ${header}` : ' but no Retry-After header';
}

export const authLoginRateLimited: ProbeModule = {
  id: 'dast.auth.login-rate-limited',
  group: 'rate',
  requirementIds: ['V6.3.1', 'V2.4.1'],
  fallback: {
    title: 'Sign-in is not rate limited',
    severity: 'high',
    cwe: ['CWE-307'],
    description: 'Many wrong passwords in a row for the same account were all answered normally — nothing slowed the attempts down.',
    impact: 'An attacker can try thousands of passwords per minute until one works.',
    fix: "Apply the 'login' rate-limit preset (5 per 15 minutes per account plus 20 per 15 minutes per address) to the sign-in route.",
    exploitability: 'trivial',
  },
  async run(ctx) {
    const user = ctx.seededUsers.find((u) => u.label === 'member2') ?? ctx.seededUsers[0];
    if (!user) return NOT_ATTEMPTED('no seeded user to try wrong passwords with');
    const expected = `repeated wrong passwords for one account are refused with 429 within ${MAX_ATTEMPTS} attempts`;
    let last;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const res = await ctx.loginAttempt(user.email, `wrong-password-attempt-${attempt}`);
      last = res;
      if (res.status === 429) {
        return pass(expected, `attempt ${attempt} was refused with 429${retryAfterNote(res.header('retry-after'))}`, res);
      }
    }
    return fail(expected, `${MAX_ATTEMPTS} wrong passwords all answered ${last?.status ?? 0}; no limit was applied`, last);
  },
};

/**
 * A six-digit code that is certainly wrong right now. Sequential guesses can hit the live code (the app accepts
 * the steps either side of the current one), which would complete the sign-in and end the test, so any guess
 * that matches a code within two steps of now is skipped.
 */
function wrongCode(seed: string, attempt: number): string {
  const live = seed ? new Set([-2, -1, 0, 1, 2].map((offset) => totp(seed, { offset }))) : new Set<string>();
  let n = 100000 + attempt;
  while (live.has(String(n))) n += 1000;
  return String(n);
}

export const authMfaRateLimited: ProbeModule = {
  id: 'dast.auth.mfa-rate-limited',
  group: 'rate',
  requirementIds: ['V6.6.3'],
  fallback: {
    title: 'One-time code entry is not rate limited',
    severity: 'high',
    cwe: ['CWE-307'],
    description: 'Wrong one-time codes could be submitted over and over without being slowed down.',
    impact: 'A six-digit code can be guessed by brute force in minutes when there is no limit.',
    fix: "Apply the 'mfa' rate-limit preset (5 per 15 minutes per account) to the one-time code route.",
  },
  async run(ctx) {
    if (!ctx.features.adminMfa && !ctx.features.userMfa) return NOT_ATTEMPTED('one-time codes are not enabled in this design');
    const admin = ctx.seededUsers.find((u) => u.mfa);
    if (!admin) return NOT_ATTEMPTED('no seeded user has a one-time code enrolled');
    const expected = `repeated wrong one-time codes are refused with 429 within ${MAX_ATTEMPTS} attempts`;
    const jar = new CookieJar();
    const first = await ctx.loginAttempt(admin.email, ctx.secrets.password, jar);
    if (!first.isRedirect()) return NOT_ATTEMPTED(`the password step answered ${first.status}, so the code step was never reached`, expected);
    const mfaPath = ctx.paths.loginMfa;
    let last;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const page = await ctx.http.get(mfaPath, { jar });
      const token = extractCsrfToken(page.body);
      const res = await ctx.http.form(mfaPath, { ...(token ? { _csrf: token } : {}), code: wrongCode(ctx.secrets.totpSeed, attempt) }, { jar });
      last = res;
      if (res.status === 429) return pass(expected, `attempt ${attempt} was refused with 429${retryAfterNote(res.header('retry-after'))}`, res);
      if (res.status === 404) return NOT_ATTEMPTED(`${mfaPath} answered 404, so there is no one-time code step to test`, expected);
    }
    return fail(expected, `${MAX_ATTEMPTS} wrong codes all answered ${last?.status ?? 0}; no limit was applied`, last);
  },
};

/** Submits a form repeatedly until it is refused with 429. */
async function untilLimited(
  ctx: ProbeContext,
  path: string,
  expected: string,
  fields: (attempt: number) => Record<string, string>,
): Promise<ProbeOutcome> {
  let last;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const jar = new CookieJar();
    const page = await ctx.http.get(path, { jar });
    if (page.status === 404) return NOT_ATTEMPTED(`${path} answered 404, so there is no such form to test`, expected);
    const token = extractCsrfToken(page.body);
    const res = await ctx.http.form(path, { ...(token ? { _csrf: token } : {}), ...fields(attempt) }, { jar });
    last = res;
    if (res.status === 429) return pass(expected, `attempt ${attempt} was refused with 429${retryAfterNote(res.header('retry-after'))}`, res);
  }
  return fail(expected, `${MAX_ATTEMPTS} submissions all answered ${last?.status ?? 0}; no limit was applied`, last);
}

export const rateRegistrationLimited: ProbeModule = {
  id: 'dast.rate.registration-limited',
  group: 'rate',
  requirementIds: ['V2.4.1'],
  fallback: {
    title: 'Account creation is not rate limited',
    severity: 'medium',
    cwe: ['CWE-799'],
    description: 'The sign-up form accepted many submissions in a row from the same address without slowing down.',
    impact: 'Someone can fill the app with junk accounts, send a flood of confirmation emails, or hide real activity.',
    fix: "Apply the 'registration' rate-limit preset (3 per hour per address) to the sign-up route.",
    exploitability: 'trivial',
  },
  async run(ctx) {
    if (!ctx.paths.register) return NOT_ATTEMPTED('this app has no sign-up form (accounts are created by an administrator)');
    const expected = `repeated sign-up submissions are refused with 429 within ${MAX_ATTEMPTS} attempts`;
    const stamp = Date.now();
    const password = `${ctx.secrets.password}Aa1`;
    return untilLimited(ctx, ctx.paths.register, expected, (n) => ({
      name: 'Rate probe',
      email: `rate-probe-${stamp}-${n}@test.local`,
      password,
      passwordConfirm: password,
    }));
  },
};

export const rateResetLimited: ProbeModule = {
  id: 'dast.rate.reset-limited',
  group: 'rate',
  requirementIds: ['V2.4.1'],
  fallback: {
    title: 'Password reset requests are not rate limited',
    severity: 'medium',
    cwe: ['CWE-799'],
    description: 'The "forgot password" form accepted many requests in a row for the same account without slowing down.',
    impact: 'Someone can bombard a person with reset emails, which is both harassment and a phishing opportunity.',
    fix: "Apply the 'reset' rate-limit preset (3 per hour per account, 10 per hour per address) to the reset route.",
    exploitability: 'trivial',
  },
  async run(ctx) {
    if (!ctx.paths.forgotPassword) return NOT_ATTEMPTED('this app has no "forgot password" form');
    const user = ctx.seededUsers.find((u) => u.label === 'member2') ?? ctx.seededUsers[0];
    if (!user) return NOT_ATTEMPTED('no seeded user to request a reset for');
    const expected = `repeated reset requests for one account are refused with 429 within ${MAX_ATTEMPTS} attempts`;
    return untilLimited(ctx, ctx.paths.forgotPassword, expected, () => ({ email: user.email }));
  },
};

export const rateXffSpoofIgnored: ProbeModule = {
  id: 'dast.rate.xff-spoof-ignored',
  group: 'rate',
  requirementIds: ['V4.1.3', 'V15.3.4'],
  fallback: {
    title: 'A forged X-Forwarded-For header resets the rate limit',
    severity: 'medium',
    cwe: ['CWE-348'],
    description: 'After sign-in was rate limited, adding a made-up X-Forwarded-For header let the attempts continue.',
    impact: 'Every anti-automation limit keyed to the visitor address can be bypassed by changing one header.',
    fix: 'Leave TRUST_PROXY_HOPS at 0 unless the app really runs behind a proxy, and take the client address only from the configured number of hops.',
  },
  async run(ctx) {
    const user = ctx.seededUsers.find((u) => u.label === 'member2') ?? ctx.seededUsers[0];
    if (!user) return NOT_ATTEMPTED('no seeded user to try wrong passwords with');
    const expected = 'once sign-in is rate limited, a forged X-Forwarded-For header does not make it work again';
    let limited;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const res = await ctx.loginAttempt(user.email, `wrong-password-xff-${attempt}`);
      if (res.status === 429) {
        limited = res;
        break;
      }
    }
    if (!limited) return NOT_ATTEMPTED('sign-in never reached its rate limit, so header spoofing could not be tested', expected);
    const spoofed = await ctx.loginAttempt(user.email, 'wrong-password-xff-spoof', new CookieJar(), {
      'X-Forwarded-For': '203.0.113.7',
      'X-Real-IP': '203.0.113.7',
    });
    if (spoofed.status === 429) return pass(expected, 'the forged header was ignored; the request stayed refused with 429', spoofed);
    return fail(expected, `the forged header let the request through again (status ${spoofed.status})`, spoofed);
  },
};

export const rateProbes: ProbeModule[] = [
  authLoginRateLimited,
  authMfaRateLimited,
  rateRegistrationLimited,
  rateResetLimited,
  rateXffSpoofIgnored,
];
