/**
 * How the runtime scanner signs in. The default bootstrap follows the template's forms (CONTRACTS §1.16: seeded
 * users, password from SECUREVIBE_TEST_PASSWORD, TOTP for the admin from SECUREVIBE_TEST_TOTP_SEED). SecureVibe's
 * self-assessment plugs in a different bootstrap (startup token exchanged for a cookie) through the same interface.
 */
import type { TemplateManifest } from '@shared/knowledge.js';
import { CookieJar, extractCsrfToken, type HttpClient, type HttpResponse } from './http.js';
import { msUntilNextStep, totp } from './totp.js';
import type { AppInstance, RoutesExport, SeededUser, Session } from './types.js';

export interface AuthBootstrapContext {
  http: HttpClient;
  app: AppInstance;
  routes: RoutesExport | undefined;
  secrets: { password: string; totpSeed: string };
  paths: { login: string; loginMfa: string; account: string };
  log(msg: string): void;
}

export interface DastAuthBootstrap {
  name: string;
  /** The users to sign in for the authorization probes. */
  seededUsers(ctx: AuthBootstrapContext, manifestTestMode?: TemplateManifest['testMode']): SeededUser[];
  /** Signs one user in. Returns undefined (after logging why) when that user cannot be signed in. */
  login(user: SeededUser, ctx: AuthBootstrapContext): Promise<Session | undefined>;
  /** One raw sign-in attempt without the second step (used by rate-limit and uniform-response probes). */
  loginAttempt(email: string, password: string, ctx: AuthBootstrapContext, jar?: CookieJar, headers?: Record<string, string>): Promise<HttpResponse>;
}

export interface StartupTokenAuthOptions {
  /** The one-time token the app prints at startup. */
  token: string;
  /** Where the token is exchanged for a session cookie. Default `/auth/token`. */
  exchangePath?: string;
  /** How the token is sent: in the query string of a GET (as the opened URL does) or in a POST body. */
  method?: 'GET' | 'POST';
  /** Query/body field name for the token. Default `token`. */
  field?: string;
  /** A JSON endpoint that returns `{ csrfToken }` for a signed-in session (apps whose pages carry no token in HTML). */
  csrfPath?: string;
  /**
   * Extra labels that sign in as the same user with a fresh session each (probes use `member2` as a throw-away
   * session). Leave out for apps where those labels must be different accounts.
   */
  extraSessionLabels?: string[];
  /** Who the resulting session belongs to, for the authorization probes. */
  user?: { label: string; email: string; role: string };
}

/**
 * Sign-in for an app that has no sign-in form: a startup token is exchanged for a session cookie. This is how
 * SecureVibe's own interface works, so its self-assessment plugs this bootstrap into the same probe suite
 * (CONTRACTS §4.3 / DESIGN §11).
 */
export function startupTokenAuthBootstrap(options: StartupTokenAuthOptions): DastAuthBootstrap {
  const exchangePath = options.exchangePath ?? '/auth/token';
  const field = options.field ?? 'token';
  const method = options.method ?? 'GET';
  const user = options.user ?? { label: 'owner', email: 'owner@localhost', role: 'owner' };

  const exchange = (token: string, ctx: AuthBootstrapContext, jar: CookieJar, headers: Record<string, string> = {}): Promise<HttpResponse> => {
    if (method === 'GET') return ctx.http.get(`${exchangePath}?${field}=${encodeURIComponent(token)}`, { jar, headers });
    return ctx.http.json(exchangePath, { [field]: token }, { jar, headers });
  };

  return {
    name: 'startup-token',

    seededUsers() {
      return [{ ...user, mfa: false }, ...(options.extraSessionLabels ?? []).map((label) => ({ ...user, label, mfa: false }))];
    },

    loginAttempt(_email, password, ctx, jar = new CookieJar(), headers = {}) {
      // The "password" stands in for the token, so a wrong-token attempt probes the same way as a wrong password.
      return exchange(password, ctx, jar, headers);
    },

    async login(seeded, ctx) {
      const jar = new CookieJar();
      const res = await exchange(options.token, ctx, jar);
      if (res.status >= 400 || !jar.sessionId()) {
        ctx.log(`[dast] the startup token was not accepted (status ${res.status})`);
        return undefined;
      }
      let csrfToken: string | undefined;
      if (options.csrfPath) {
        const status = await ctx.http.get(options.csrfPath, { jar, headers: { Accept: 'application/json' } });
        csrfToken = status.json<{ csrfToken?: string }>()?.csrfToken;
      }
      return { label: seeded.label, email: seeded.email, role: seeded.role, jar, ...(csrfToken ? { csrfToken } : {}) };
    },
  };
}

export const CONTRACT_SEEDED_USERS: { label: string; email: string }[] = [
  { label: 'admin', email: 'admin@test.local' },
  { label: 'staff', email: 'staff@test.local' },
  { label: 'member', email: 'member@test.local' },
  { label: 'member2', email: 'member2@test.local' },
];

export function labelFor(email: string): string {
  return email.split('@')[0] ?? email;
}

function contractUsers(roles: string[] | undefined, adminRole: string | undefined): SeededUser[] {
  const nonAdmin = (roles ?? []).filter((r) => r !== (adminRole ?? 'admin'));
  const first = nonAdmin[0] ?? 'member';
  const last = nonAdmin[nonAdmin.length - 1] ?? 'member';
  return [
    { label: 'admin', email: 'admin@test.local', role: adminRole ?? 'admin', mfa: true },
    { label: 'staff', email: 'staff@test.local', role: first, mfa: false },
    { label: 'member', email: 'member@test.local', role: last, mfa: false },
    { label: 'member2', email: 'member2@test.local', role: last, mfa: false },
  ];
}

const MFA_LOCATION = /mfa|totp|2fa|verify|one-time/i;

/** Sign-in through the template's HTML forms: /login (email, password, _csrf) then /login/mfa (code, _csrf). */
export const formAuthBootstrap: DastAuthBootstrap = {
  name: 'form-login',

  seededUsers(ctx, manifestTestMode) {
    const exported = ctx.routes?.seededUsers;
    if (exported && exported.length > 0) {
      return exported.map((u) => ({ label: labelFor(u.email), email: u.email, role: u.role, mfa: u.mfa ?? labelFor(u.email) === 'admin' }));
    }
    if (manifestTestMode && manifestTestMode.seededUsers.length > 0) {
      return manifestTestMode.seededUsers.map((u) => ({ label: labelFor(u.email), email: u.email, role: u.role, mfa: labelFor(u.email) === 'admin' }));
    }
    return contractUsers(ctx.routes?.roles, ctx.routes?.adminRole);
  },

  async loginAttempt(email, password, ctx, jar = new CookieJar(), headers = {}) {
    const page = await ctx.http.get(ctx.paths.login, { jar });
    const token = extractCsrfToken(page.body);
    return ctx.http.form(ctx.paths.login, { ...(token ? { _csrf: token } : {}), email, password }, { jar, headers });
  },

  async login(user, ctx) {
    const jar = new CookieJar();
    const res = await this.loginAttempt(user.email, ctx.secrets.password, ctx, jar);
    if (!res.isRedirect()) {
      ctx.log(`[dast] could not sign in ${user.email}: status ${res.status}`);
      return undefined;
    }
    if (MFA_LOCATION.test(res.location())) {
      if (!user.mfa) {
        ctx.log(`[dast] ${user.email} was sent to the one-time code step but has no seed`);
        return undefined;
      }
      // Never submit a code that is about to expire.
      if (msUntilNextStep() < 3_000) await new Promise((r) => setTimeout(r, msUntilNextStep() + 100));
      const mfaPath = res.location().startsWith('http') ? new URL(res.location()).pathname : res.location() || ctx.paths.loginMfa;
      const mfaPage = await ctx.http.get(mfaPath, { jar });
      const token = extractCsrfToken(mfaPage.body);
      const mfaRes = await ctx.http.form(ctx.paths.loginMfa, { ...(token ? { _csrf: token } : {}), code: totp(ctx.secrets.totpSeed) }, { jar });
      if (!mfaRes.isRedirect() || MFA_LOCATION.test(mfaRes.location())) {
        ctx.log(`[dast] the one-time code for ${user.email} was not accepted (status ${mfaRes.status})`);
        return undefined;
      }
    }
    if (!jar.sessionId()) {
      ctx.log(`[dast] sign-in for ${user.email} redirected but set no session cookie`);
      return undefined;
    }
    return { label: user.label, email: user.email, role: user.role, jar };
  },
};
