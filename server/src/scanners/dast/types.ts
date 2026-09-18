/**
 * Types shared by the runtime scanner (DAST): what the harness gives a probe, what a probe returns, and the
 * shape of the generated app's test-mode endpoints (CONTRACTS §1.16, §2).
 */
import type { BuildSpec } from '@shared/design.js';
import type { Finding, Severity } from '@shared/findings.js';
import type { CookieJar, HttpClient, HttpResponse } from './http.js';

/** Probe groups in execution order (CONTRACTS §2; `auth` holds the sign-in probes that are not rate limits). */
export const PROBE_GROUPS = [
  'headers',
  'leak',
  'errors',
  'input',
  'csrf',
  'session',
  'auth',
  'authz',
  'uploads',
  'ai',
  'redirect',
  'xss',
  'log',
  'rate',
] as const;
export type ProbeGroup = (typeof PROBE_GROUPS)[number];

/** Which app start a probe needs: the seeded test-mode instance, the production-mode instance, or a TLS one. */
export type ProbePhase = 'test' | 'production' | 'selfsigned';

export interface RouteInfo {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  auth: string;
  roles?: string[] | null;
  owner?: { entity: string; param: string; ownerField?: string } | null;
  entity?: string | null;
  kind?: 'page' | 'api';
  csrf?: boolean;
  rateLimit?: string;
  idempotent?: boolean;
  summary?: string;
  params?: string[];
  /** JSON Schema of the validated request body, when the app exports it (test mode). */
  bodySchema?: unknown;
}

export interface EntityInfo {
  name: string;
  ownerField: string;
  sample: { id: string | number | null };
}

export interface SeededUser {
  email: string;
  role: string;
  /** Whether the user has a one-time code (TOTP) enrolled. */
  mfa: boolean;
  /** Stable label used by probes: admin, staff, member, member2. */
  label: string;
}

export interface RoutesExport {
  routes: RouteInfo[];
  roles: string[];
  adminRole?: string;
  entities: EntityInfo[];
  seededUsers?: { email: string; role: string; mfa?: boolean }[];
}

export interface SecurityEvent {
  ts: string;
  event: string;
  reqId?: string;
  userId?: string | number | null;
  ip?: string;
  route?: string;
  outcome?: string;
  [key: string]: unknown;
}

/** A signed-in browser: its cookie jar plus who it is. */
export interface Session {
  label: string;
  email: string;
  role: string;
  jar: CookieJar;
  /** Last CSRF token fetched for this session (refreshed by `ctx.csrf`). */
  csrfToken?: string;
}

export interface AppInstance {
  phase: ProbePhase;
  baseUrl: string;
  port: number;
  pid: number | undefined;
  dataDir: string;
  env: Record<string, string>;
  tlsMode: 'off' | 'selfsigned' | 'proxy';
  sandboxMode: string;
  /** Captured stdout/stderr so far. */
  output(): { stdout: string; stderr: string };
  /** Resets the app's rate limiters directly (an app started in-process); otherwise the test-mode endpoint is used. */
  resetRateLimits?(): Promise<boolean>;
  stop(): Promise<void>;
}

/** What every probe receives. Everything that needs the app is behind small async helpers. */
export interface ProbeContext {
  phase: ProbePhase;
  app: AppInstance;
  http: HttpClient;
  buildSpec: BuildSpec;
  features: BuildSpec['features'];
  appDir: string;
  /** Route registry export (test phase only). */
  routes: RoutesExport | undefined;
  seededUsers: SeededUser[];
  /** Sessions by label (admin, staff, member, member2) — only those that could sign in. */
  sessions: Map<string, Session>;
  /** The test password and TOTP seed the harness generated. */
  secrets: { password: string; totpSeed: string };
  /** Fetches a CSRF token for a session (from `/account` or `fromPath`), caching it on the session. */
  csrf(session: Session | undefined, fromPath?: string): Promise<string | undefined>;
  /** Security events emitted since an ISO timestamp (test phase). */
  events(sinceIso: string): Promise<SecurityEvent[]>;
  resetRateLimits(): Promise<boolean>;
  /** Signs a seeded user in again on a fresh jar (after probes that destroy a session). */
  login(label: string): Promise<Session | undefined>;
  /** Raw sign-in attempt (no MFA step): returns the response of POST /login. */
  loginAttempt(email: string, password: string, jar?: CookieJar, headers?: Record<string, string>): Promise<HttpResponse>;
  totp(seedBase32: string): string;
  log(msg: string): void;
  /** A GET page route with the given auth that needs no parameters, for probes that need "any signed-in page". */
  pageFor(auth: 'user' | 'admin'): string | undefined;
  /** Ready-made request paths derived from the registry (undefined when the app has no such route). */
  paths: {
    login: string;
    loginMfa: string;
    logout: string;
    account: string;
    register?: string;
    forgotPassword?: string;
    changePassword?: string;
    uploads?: string;
    ai?: string;
    aiKillSwitch?: string;
    adminPage?: string;
    notesApi?: string;
  };
}

/** One failure inside a probe that checks many routes; each becomes its own finding. */
export interface ProbeFailure {
  endpoint: string;
  observed: string;
  requestExcerpt?: string;
  responseExcerpt?: string;
}

/** What a probe's `run` returns; the runner fills in id, group and requirement ids. */
export interface ProbeOutcome {
  passed: boolean | null;
  expected: string;
  observed: string;
  /** Why the probe could not run (when `passed` is null). */
  reason?: string;
  requestExcerpt?: string;
  responseExcerpt?: string;
  endpoint?: string;
  failures?: ProbeFailure[];
  /** Overrides for the finding produced on failure (severity, extra description). */
  findingOnFail?: Partial<Finding>;
}

export interface ProbeResult extends ProbeOutcome {
  id: string;
  group: ProbeGroup;
  phase: ProbePhase;
  requirementIds: string[];
  durationMs: number;
}

/** Built-in remediation used when data/knowledge/remediation.json has no entry for the probe id. */
export interface ProbeFallback {
  title: string;
  severity: Severity;
  cwe: string[];
  description: string;
  impact: string;
  fix: string;
  steps?: string[];
  references?: string[];
  exploitability?: Finding['exploitability'];
  confidence?: Finding['confidence'];
}

export interface ProbeModule {
  id: string;
  group: ProbeGroup;
  /** Which app start this probe runs against. Default: 'test'. */
  phase?: ProbePhase;
  requirementIds: string[];
  fallback: ProbeFallback;
  run(ctx: ProbeContext): Promise<ProbeOutcome>;
}

export const NOT_ATTEMPTED = (reason: string, expected = ''): ProbeOutcome => ({
  passed: null,
  expected,
  observed: 'not attempted',
  reason,
});

export function isMutating(method: string): boolean {
  return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
}

export function isDenied(status: number): boolean {
  return status === 401 || status === 403 || status === 404 || (status >= 300 && status < 400);
}
