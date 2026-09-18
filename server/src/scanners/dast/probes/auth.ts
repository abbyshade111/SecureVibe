/**
 * Sign-in probes that are not rate limits: weak passwords refused, password fields, uniform responses for
 * unknown accounts and password resets, and admin one-time-code enforcement.
 */
import { CookieJar, extractCsrfToken } from '../http.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule } from '../types.js';
import { fail, normalizeHtml, pass } from './util.js';

const WEAK_PASSWORDS = ['password1234', 'short', 'qwerty123456'];

export const authWeakPasswordRejected: ProbeModule = {
  id: 'dast.auth.weak-password-rejected',
  group: 'auth',
  requirementIds: ['V6.2.1', 'V6.2.4', 'V6.2.5'],
  fallback: {
    title: 'Weak passwords are accepted',
    severity: 'high',
    cwe: ['CWE-521'],
    description: 'A very common or too-short password was accepted when creating an account or changing a password.',
    impact: 'Accounts with weak passwords are taken over by simple guessing.',
    fix: 'Enforce at least 12 characters and refuse passwords from the common-password list.',
  },
  async run(ctx) {
    const expected = 'passwords shorter than 12 characters or on the common list are refused with 400';
    if (ctx.paths.register) {
      // Registration is limited per client; earlier probes may have used the allowance, which says nothing about passwords.
      await ctx.resetRateLimits();
      const jar = new CookieJar();
      const page = await ctx.http.get(ctx.paths.register, { jar });
      const token = extractCsrfToken(page.body);
      for (const weak of WEAK_PASSWORDS) {
        const res = await ctx.http.form(ctx.paths.register, { _csrf: token ?? '', name: 'Probe', email: `probe-${Date.now()}@test.local`, password: weak, passwordConfirm: weak }, { jar });
        if (res.status === 429) return NOT_ATTEMPTED('registration was rate-limited before the weak passwords could be tried', expected);
        if (res.status !== 400) return fail(expected, `registration accepted "${weak}" (status ${res.status})`, res);
      }
      return pass(expected, `registration refused ${WEAK_PASSWORDS.length} weak passwords with 400`);
    }
    const session = await ctx.login('member2');
    if (!session || !ctx.paths.changePassword) return NOT_ATTEMPTED(session ? 'no registration or change-password route is registered' : 'could not sign in a throw-away session', expected);
    const page = await ctx.http.get(ctx.paths.changePassword, { jar: session.jar });
    const token = extractCsrfToken(page.body) ?? (await ctx.csrf(session));
    for (const weak of WEAK_PASSWORDS) {
      const res = await ctx.http.form(ctx.paths.changePassword, { _csrf: token ?? '', currentPassword: ctx.secrets.password, newPassword: weak, newPasswordConfirm: weak }, { jar: session.jar });
      if (res.status === 429) return NOT_ATTEMPTED('the password change was rate-limited before the weak passwords could be tried', expected);
      if (res.status !== 400) return fail(expected, `password change accepted "${weak}" (status ${res.status})`, res);
    }
    return pass(expected, `password change refused ${WEAK_PASSWORDS.length} weak passwords with 400`);
  },
};

export const authPasswordFieldType: ProbeModule = {
  id: 'dast.auth.password-field-type',
  group: 'auth',
  requirementIds: ['V6.2.6', 'V6.2.7'],
  fallback: {
    title: 'Password field is not a proper password input',
    severity: 'low',
    cwe: ['CWE-549'],
    description: 'The sign-in page has no <input type="password"> for the password, or it blocks pasting.',
    impact: 'Passwords shown on screen are shoulder-surfed; blocking paste discourages password managers.',
    fix: 'Use <input type="password" name="password" autocomplete="current-password"> and never block paste.',
  },
  async run(ctx) {
    const expected = 'the sign-in page has <input type="password" name="password"> with paste allowed';
    const res = await ctx.http.get(ctx.paths.login);
    const inputs = res.body.match(/<input[^>]*>/gi) ?? [];
    const field = inputs.find((i) => /name=["']password["']/i.test(i));
    if (!field) return NOT_ATTEMPTED('no password field found on the sign-in page', expected);
    if (!/type=["']password["']/i.test(field)) return fail(expected, `the password input is ${/type=["']([^"']+)["']/i.exec(field)?.[1] ?? 'untyped'}`, res);
    if (/onpaste=|autocomplete=["']off["']/i.test(field)) return fail(expected, 'the password input blocks paste or autocomplete', res);
    return pass(expected, 'type="password" with paste allowed', res);
  },
};

export const authUniformUnknownUser: ProbeModule = {
  id: 'dast.auth.uniform-unknown-user',
  group: 'auth',
  requirementIds: ['V6.3.1'],
  fallback: {
    title: 'Sign-in reveals whether an account exists',
    severity: 'medium',
    cwe: ['CWE-204'],
    description: 'A wrong password for a real account and a sign-in for an unknown email produced different responses.',
    impact: 'Attackers can list valid accounts before guessing passwords or phishing.',
    fix: 'Return the same status and message for unknown accounts and wrong passwords, and verify a dummy hash for unknown accounts.',
  },
  async run(ctx) {
    const known = ctx.seededUsers.find((u) => u.label === 'member2') ?? ctx.seededUsers[0];
    if (!known) return NOT_ATTEMPTED('no seeded user');
    const expected = 'wrong password (known account) and unknown account answer the same status and the same page text';
    const a = await ctx.loginAttempt(known.email, 'definitely-not-the-password-1');
    const b = await ctx.loginAttempt(`unknown-${Date.now()}@test.local`, 'definitely-not-the-password-1');
    if (a.status !== b.status) return fail(expected, `known account ${a.status} vs unknown ${b.status}`, b);
    if (normalizeHtml(a.body) !== normalizeHtml(b.body)) return fail(expected, 'the two response bodies differ (timing was not measured)', b);
    return pass(expected, `both answered ${a.status} with the same page (timing was not measured)`, b);
  },
};

export const authResetUniformResponse: ProbeModule = {
  id: 'dast.auth.reset-uniform-response',
  group: 'auth',
  requirementIds: ['V6.4.3', 'V6.3.1'],
  fallback: {
    title: 'Password reset reveals whether an account exists',
    severity: 'medium',
    cwe: ['CWE-204'],
    description: 'Requesting a password reset for a known and an unknown email produced different responses.',
    impact: 'The reset form becomes an account enumeration oracle.',
    fix: 'Always show the same "check your email" page whether or not the account exists.',
  },
  async run(ctx) {
    if (!ctx.paths.forgotPassword) return NOT_ATTEMPTED('no forgot-password route is registered');
    const known = ctx.seededUsers.find((u) => u.label === 'member2') ?? ctx.seededUsers[0];
    if (!known) return NOT_ATTEMPTED('no seeded user');
    const expected = 'reset requests for a known and an unknown email answer the same status and page';
    const request = async (email: string) => {
      const jar = new CookieJar();
      const page = await ctx.http.get(ctx.paths.forgotPassword!, { jar });
      const token = extractCsrfToken(page.body);
      return ctx.http.form(ctx.paths.forgotPassword!, { _csrf: token ?? '', email }, { jar });
    };
    const a = await request(known.email);
    const b = await request(`unknown-${Date.now()}@test.local`);
    if (a.status !== b.status) return fail(expected, `known ${a.status} vs unknown ${b.status}`, b);
    if (a.isRedirect() && a.location() !== b.location()) return fail(expected, 'different redirect targets', b);
    if (!a.isRedirect() && normalizeHtml(a.body) !== normalizeHtml(b.body)) return fail(expected, 'the two response bodies differ', b);
    return pass(expected, `both answered ${a.status} identically`, b);
  },
};

export const authAdminMfaEnforced: ProbeModule = {
  id: 'dast.auth.admin-mfa-enforced',
  group: 'auth',
  requirementIds: ['V6.3.3', 'V6.5.1'],
  fallback: {
    title: 'Administrator can skip the one-time code',
    severity: 'high',
    cwe: ['CWE-308'],
    description: 'After entering only the password, the administrator session could already open an admin page.',
    impact: 'A stolen admin password alone is enough to take over the app.',
    fix: 'Require the TOTP step for administrators and keep sessions unverified until it succeeds.',
  },
  async run(ctx) {
    if (!ctx.features.adminMfa) return NOT_ATTEMPTED('administrator one-time codes are not enabled in this design');
    const admin = ctx.seededUsers.find((u) => u.label === 'admin');
    const adminPage = ctx.paths.adminPage;
    if (!admin) return NOT_ATTEMPTED('no seeded administrator');
    const expected = 'after the password step the admin is sent to the one-time code page and admin pages stay closed';
    const jar = new CookieJar();
    const res = await ctx.loginAttempt(admin.email, ctx.secrets.password, jar);
    if (!res.isRedirect()) return NOT_ATTEMPTED(`admin sign-in answered ${res.status}`, expected);
    if (!/mfa|totp|2fa|verify|one-time/i.test(res.location())) return fail(expected, `password alone redirected to ${res.location()} (no one-time code step)`, res);
    if (adminPage) {
      const page = await ctx.http.get(adminPage, { jar });
      if (page.status === 200) return fail(expected, `${adminPage} opened before the one-time code was entered`, page);
      return pass(expected, `sent to ${res.location()}; ${adminPage} answered ${page.status} before the code`, page);
    }
    return pass(expected, `sent to ${res.location()} (no admin page registered to double-check)`, res);
  },
};

export function seededAdmin(ctx: ProbeContext): { email: string } | undefined {
  return ctx.seededUsers.find((u) => u.label === 'admin');
}

export const authProbes: ProbeModule[] = [authPasswordFieldType, authWeakPasswordRejected, authUniformUnknownUser, authResetUniformResponse, authAdminMfaEnforced];
