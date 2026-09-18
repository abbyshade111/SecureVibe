/**
 * Test harness: starts the application as a child process in test-bootstrap mode (contract §1.16) with
 * generated secrets and a throw-away DATA_DIR, and offers a cookie jar, login (including the TOTP step),
 * CSRF token extraction, security-event and database access, and a stop() that kills the process group.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fields, headers as headerNames, paths, users } from './conventions.ts';
import { featureFromFile, templateRoot, type FeatureId } from './features.ts';
import { freshTotp, randomTotpSeed, waitForNextStep } from './totp.ts';

export { templateRoot };

// ---------------------------------------------------------------------------------------------------
// Cookie jar
// ---------------------------------------------------------------------------------------------------

export class CookieJar {
  readonly cookies = new Map<string, string>();

  absorb(res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const eq = pair!.indexOf('=');
      if (eq < 0) continue;
      const name = pair!.slice(0, eq).trim();
      const value = pair!.slice(eq + 1).trim();
      const expired = attrs.some((a) => {
        const [k, v] = a.trim().split('=');
        const key = (k ?? '').toLowerCase();
        if (key === 'max-age') return Number(v) <= 0;
        if (key === 'expires') return new Date(v ?? '').getTime() < Date.now();
        return false;
      });
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  header(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  /** The session cookie value (`sid`, or `__Host-sid` in TLS modes). */
  sessionId(): string | undefined {
    return this.cookies.get('sid') ?? this.cookies.get('__Host-sid');
  }

  clone(): CookieJar {
    const j = new CookieJar();
    for (const [k, v] of this.cookies) j.cookies.set(k, v);
    return j;
  }
}

// ---------------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------------

export interface RouteInfo {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  auth: string;
  roles?: string[];
  owner?: { entity: string; param: string; ownerField?: string };
  csrf?: boolean;
  rateLimit?: string;
  idempotent?: boolean;
  entity?: string;
  kind?: 'page' | 'api';
  summary?: string;
}

export interface RoutesExport {
  routes: RouteInfo[];
  roles: string[];
  entities: { name: string; ownerField: string; sample: { id: string | number } }[];
}

export interface SecurityEvent {
  ts: string;
  event: string;
  reqId?: string;
  userId?: string | number;
  ip?: string;
  route?: string;
  outcome?: 'success' | 'failure' | 'blocked';
  [k: string]: unknown;
}

export interface FetchOptions extends Omit<RequestInit, 'headers' | 'body'> {
  jar?: CookieJar;
  headers?: Record<string, string>;
  body?: RequestInit['body'];
  /** Set to false to omit the same-origin Origin / Sec-Fetch-Site headers on state-changing requests. */
  sameOrigin?: boolean;
}

export interface StartOptions {
  env?: Record<string, string | undefined>;
  /** Reuse the DATA_DIR of a previous instance (for restart scenarios). */
  dataDir?: string;
  /** Production mode: NODE_ENV=production, no test-mode flag, no seeded users. Ready is detected via /healthz. */
  mode?: 'test' | 'production';
  /** Fail instead of throwing when the process exits early (returns the exit info in `startupError`). */
  allowStartupFailure?: boolean;
}

export interface StartupFailure {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

// ---------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------

export function b64(bytes = 32): string {
  return randomBytes(bytes).toString('base64');
}

export function randomPassword(length = 24): string {
  return randomBytes(length).toString('base64url').slice(0, length);
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export function formBody(data: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) if (v !== undefined) p.append(k, String(v));
  return p.toString();
}

/** Extracts the CSRF token from a rendered page (hidden field or meta tag). */
export function extractCsrfToken(html: string): string | undefined {
  const patterns = [
    new RegExp(`name=["']${fields.csrf}["'][^>]*value=["']([^"']+)["']`),
    new RegExp(`value=["']([^"']+)["'][^>]*name=["']${fields.csrf}["']`),
    /<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']+)["']/,
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']csrf-token["']/,
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m?.[1]) return m[1];
  }
  return undefined;
}

export function isRedirect(res: Response): boolean {
  return res.status >= 300 && res.status < 400;
}

export function locationOf(res: Response): string {
  return res.headers.get('location') ?? '';
}

/** Standard generated environment for one app instance. */
export function generateEnv(dataDir: string): Record<string, string> {
  return {
    NODE_ENV: 'test',
    SECUREVIBE_TEST_MODE: '1',
    PORT: '0',
    DATA_DIR: dataDir,
    SESSION_SECRET: b64(32),
    FIELD_KEYS: `1:${b64(32)}`,
    ACTIVE_FIELD_KEY: '1',
    TOKEN_HMAC_KEY: b64(32),
    SECUREVIBE_TEST_PASSWORD: randomPassword(24),
    SECUREVIBE_TEST_TOTP_SEED: randomTotpSeed(),
    EXAMPLE_FEATURE: '1',
    LOG_LEVEL: 'info',
    LOG_FILE: join(dataDir, 'app.log'),
    OUTBOUND_ALLOWED_HOSTS: '',
    // The tests talk to the app over plain http on loopback whatever the app's own .env says about its deployment
    // (a self-signed certificate or a reverse proxy); tests that need proxy hops set them explicitly.
    TLS_MODE: 'off',
    TRUST_PROXY_HOPS: '0',
    BIND_LAN: '0',
  };
}

function childEnv(extra: Record<string, string | undefined>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ']) {
    const v = process.env[k];
    if (v) env[k] = v;
  }
  for (const [k, v] of Object.entries(extra)) if (v !== undefined) env[k] = v;
  return env;
}

// ---------------------------------------------------------------------------------------------------
// Running app
// ---------------------------------------------------------------------------------------------------

export class RunningApp {
  readonly baseUrl: string;
  readonly child: ChildProcess | undefined;
  readonly port: number;
  readonly dataDir: string;
  readonly env: Record<string, string>;
  readonly output: { stdout: string; stderr: string };
  private readonly ownsDataDir: boolean;
  private routesCache?: RoutesExport;
  startupError?: StartupFailure;

  constructor(
    child: ChildProcess | undefined,
    port: number,
    dataDir: string,
    env: Record<string, string>,
    ownsDataDir: boolean,
    output: { stdout: string; stderr: string },
  ) {
    this.child = child;
    this.port = port;
    this.dataDir = dataDir;
    this.env = env;
    this.ownsDataDir = ownsDataDir;
    this.output = output;
    this.baseUrl = `http://127.0.0.1:${port}`;
  }

  get password(): string {
    return this.env.SECUREVIBE_TEST_PASSWORD!;
  }

  get totpSeed(): string {
    return this.env.SECUREVIBE_TEST_TOTP_SEED!;
  }

  get pid(): number | undefined {
    return this.child?.pid;
  }

  origin(): string {
    return this.baseUrl;
  }

  // ---- HTTP -----------------------------------------------------------------------------------

  async fetch(path: string, opts: FetchOptions = {}): Promise<Response> {
    const { jar, headers = {}, sameOrigin = true, ...init } = opts;
    const method = (init.method ?? 'GET').toUpperCase();
    const h: Record<string, string> = { ...headers };
    if (jar && jar.header() && !('cookie' in lowerKeys(h))) h.Cookie = jar.header();
    if (sameOrigin && method !== 'GET' && method !== 'HEAD') {
      const lk = lowerKeys(h);
      if (!('origin' in lk)) h.Origin = this.baseUrl;
      if (!('sec-fetch-site' in lk)) h['Sec-Fetch-Site'] = 'same-origin';
    }
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    const res = await fetch(url, { ...init, method, headers: h, redirect: 'manual' });
    jar?.absorb(res);
    return res;
  }

  async page(path: string, jar?: CookieJar, headers?: Record<string, string>): Promise<{ res: Response; html: string }> {
    const res = await this.fetch(path, { jar, headers });
    return { res, html: await res.text() };
  }

  /** CSRF token for `jar` taken from `path` (defaults to the login page for anonymous jars, /account otherwise). */
  async csrfToken(pathOrHtml?: string, jar?: CookieJar): Promise<string> {
    if (pathOrHtml && pathOrHtml.includes('<')) {
      const t = extractCsrfToken(pathOrHtml);
      if (!t) throw new Error('no CSRF token found in the supplied HTML');
      return t;
    }
    const path = pathOrHtml ?? (jar?.sessionId() ? paths.account : paths.login);
    const { res, html } = await this.page(path, jar);
    const token = extractCsrfToken(html);
    if (!token) throw new Error(`no CSRF token found on ${path} (status ${res.status})`);
    return token;
  }

  /** Submits a form (application/x-www-form-urlencoded) with a CSRF token fetched from `csrfFrom` (or `path`). */
  async submitForm(
    path: string,
    data: Record<string, string | number | boolean | undefined>,
    jar: CookieJar,
    opts: { csrfFrom?: string; csrfToken?: string | null; headers?: Record<string, string>; sameOrigin?: boolean; method?: string } = {},
  ): Promise<Response> {
    let token = opts.csrfToken;
    if (token === undefined) {
      const from = opts.csrfFrom ?? path;
      const { html } = await this.page(from, jar);
      token = extractCsrfToken(html) ?? (await this.csrfToken(undefined, jar));
    }
    const body = formBody({ ...(token ? { [fields.csrf]: token } : {}), ...data });
    return this.fetch(path, {
      method: opts.method ?? 'POST',
      jar,
      sameOrigin: opts.sameOrigin,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'text/html', ...(opts.headers ?? {}) },
      body,
    });
  }

  /** Sends JSON with the CSRF header (token fetched from a page unless given). */
  async json(
    method: string,
    path: string,
    body: unknown,
    jar?: CookieJar,
    opts: { csrfToken?: string | null; headers?: Record<string, string>; sameOrigin?: boolean; raw?: string } = {},
  ): Promise<Response> {
    let token = opts.csrfToken;
    if (token === undefined && jar && method !== 'GET') token = await this.csrfToken(undefined, jar);
    return this.fetch(path, {
      method,
      jar,
      sameOrigin: opts.sameOrigin,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(token ? { [headerNames.csrf]: token } : {}),
        ...(opts.headers ?? {}),
      },
      body: opts.raw ?? (body === undefined ? undefined : JSON.stringify(body)),
    });
  }

  // ---- Authentication ----------------------------------------------------------------------------

  /** True when `jar` holds a fully authenticated session (the account page renders). */
  async isAuthenticated(jar: CookieJar): Promise<boolean> {
    const res = await this.fetch(paths.account, { jar });
    await res.text();
    return res.status === 200;
  }

  /**
   * Logs in with the seeded test password (or `password`) and completes the TOTP step for accounts with
   * MFA enrolled (using the seeded TOTP seed unless `totpSeed` is given). Returns a cookie jar.
   */
  async login(
    email: string,
    opts: { password?: string; totpSeed?: string; code?: string; jar?: CookieJar; skipMfa?: boolean; next?: string } = {},
  ): Promise<CookieJar> {
    const jar = opts.jar ?? new CookieJar();
    const loginPath = opts.next ? `${paths.login}?${fields.next}=${encodeURIComponent(opts.next)}` : paths.login;
    const res = await this.submitForm(
      paths.login,
      { [fields.email]: email, [fields.password]: opts.password ?? this.password, ...(opts.next ? { [fields.next]: opts.next } : {}) },
      jar,
      { csrfFrom: loginPath },
    );
    const text = await res.text();
    if (!isRedirect(res)) {
      throw new Error(`login for ${email} did not redirect (status ${res.status}): ${text.slice(0, 300)}`);
    }
    const location = locationOf(res);
    if (/mfa|totp|2fa|verify/i.test(location) && !opts.skipMfa) {
      const seed = opts.totpSeed ?? (email === users.admin ? this.totpSeed : undefined);
      if (!opts.code && !seed) throw new Error(`login for ${email} requires a second factor but no TOTP seed or code was given`);
      // A TOTP step is accepted only once per account (replay prevention), and tests sign the same account in
      // repeatedly: ask for a code from a step this harness has not used yet, and if the app still refuses it,
      // wait for the next step and present a fresh one before reporting a failure.
      for (let attempt = 0; ; attempt += 1) {
        const code = opts.code ?? (await freshTotp(seed!));
        const mfaRes = await this.submitMfa(jar, code, location);
        const mfaText = await mfaRes.text();
        if (isRedirect(mfaRes) && !/mfa|totp|2fa|verify/i.test(locationOf(mfaRes))) break;
        if (opts.code !== undefined || attempt >= 1 || mfaRes.status !== 400) {
          throw new Error(`second factor rejected for ${email} (status ${mfaRes.status}): ${mfaText.slice(0, 300)}`);
        }
        await waitForNextStep();
      }
    }
    return jar;
  }

  /** Posts the second factor. `from` is the MFA page (used for the CSRF token). */
  submitMfa(jar: CookieJar, code: string, from: string = paths.loginMfa): Promise<Response> {
    const csrfFrom = from.startsWith('http') ? new URL(from).pathname + new URL(from).search : from;
    return this.submitForm(paths.loginMfa, { [fields.code]: code }, jar, { csrfFrom });
  }

  /** Posts the login form without following the MFA step. */
  loginRaw(email: string, password: string, jar = new CookieJar(), headers?: Record<string, string>): Promise<Response> {
    return this.submitForm(paths.login, { [fields.email]: email, [fields.password]: password }, jar, { csrfFrom: paths.login, headers });
  }

  async canLogin(email: string, password: string, totpSeed?: string): Promise<boolean> {
    try {
      const jar = await this.login(email, { password, totpSeed });
      return await this.isAuthenticated(jar);
    } catch {
      return false;
    }
  }

  async logout(jar: CookieJar): Promise<Response> {
    return this.submitForm(paths.logout, {}, jar, { csrfFrom: paths.account });
  }

  /** Re-authenticates (password + TOTP when enrolled) so sensitive account changes are allowed for 5 minutes. */
  async reauth(jar: CookieJar, opts: { password?: string; totpSeed?: string } = {}): Promise<Response> {
    const data: Record<string, string> = { [fields.password]: opts.password ?? this.password };
    if (opts.totpSeed) data[fields.code] = await freshTotp(opts.totpSeed);
    return this.submitForm(paths.reauth, data, jar, { csrfFrom: paths.reauth });
  }

  // ---- Test-mode endpoints -------------------------------------------------------------------------

  async routes(): Promise<RoutesExport> {
    if (this.routesCache) return this.routesCache;
    const res = await this.fetch(paths.testRoutes);
    if (res.status !== 200) throw new Error(`${paths.testRoutes} returned ${res.status}`);
    this.routesCache = (await res.json()) as RoutesExport;
    return this.routesCache;
  }

  async findRoute(method: string, pathPattern: RegExp): Promise<RouteInfo | undefined> {
    const { routes } = await this.routes();
    return routes.find((r) => r.method === method.toUpperCase() && pathPattern.test(r.path));
  }

  async hasRoute(method: string, pathPattern: RegExp): Promise<boolean> {
    return (await this.findRoute(method, pathPattern)) !== undefined;
  }

  async events(since?: string): Promise<SecurityEvent[]> {
    const q = since ? `?since=${encodeURIComponent(since)}` : '';
    const res = await this.fetch(`${paths.testEvents}${q}`);
    if (res.status !== 200) throw new Error(`${paths.testEvents} returned ${res.status}`);
    const body = (await res.json()) as SecurityEvent[] | { events: SecurityEvent[] };
    return Array.isArray(body) ? body : body.events;
  }

  async eventsNamed(name: string, since?: string): Promise<SecurityEvent[]> {
    return (await this.events(since)).filter((e) => e.event === name);
  }

  /** Waits (up to `timeoutMs`) for an event to appear and returns the matching events. */
  async waitForEvent(name: string, since?: string, predicate?: (e: SecurityEvent) => boolean, timeoutMs = 5_000): Promise<SecurityEvent[]> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = (await this.eventsNamed(name, since)).filter((e) => (predicate ? predicate(e) : true));
      if (found.length > 0 || Date.now() > deadline) return found;
      await sleep(150);
    }
  }

  async resetRateLimits(): Promise<void> {
    const res = await this.fetch(paths.testResetRateLimits, { method: 'POST' });
    await res.text();
    if (res.status >= 400) throw new Error(`${paths.testResetRateLimits} returned ${res.status}`);
  }

  /**
   * Feature check for optional-feature tests: the features file decides when present; otherwise the
   * live route registry is consulted (a mounted feature exposes its routes).
   */
  async featureEnabled(id: FeatureId): Promise<boolean> {
    const fromFile = featureFromFile(id);
    if (fromFile !== undefined) return fromFile;
    const probes: Partial<Record<FeatureId, RegExp>> = {
      uploads: /^\/uploads/,
      ai: /^\/ai(\/|$)/,
      'ai-actions': /^\/ai\/confirm/,
      'ai-history': /^\/ai\/reset/,
      'public-api': /api-keys|apikeys/,
      email: /forgot-password/,
      scheduler: /^\/admin\/scheduler/,
      example: /^\/api\/notes/,
    };
    const re = probes[id];
    if (!re) return false;
    const { routes } = await this.routes();
    return routes.some((r) => re.test(r.path));
  }

  // ---- Files and database ------------------------------------------------------------------------

  /** Path of the SQLite database file inside DATA_DIR. */
  dbPath(): string {
    const candidates = readdirSync(this.dataDir).filter((f) => /\.(db|sqlite|sqlite3)$/.test(f));
    if (candidates.length === 0) throw new Error(`no SQLite database file found in ${this.dataDir}`);
    return join(this.dataDir, candidates[0]!);
  }

  db(): DatabaseSync {
    return new DatabaseSync(this.dbPath());
  }

  dbTables(): string[] {
    const db = this.db();
    try {
      return (db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[]).map(
        (r) => r.name,
      );
    } finally {
      db.close();
    }
  }

  dbColumns(table: string): string[] {
    const db = this.db();
    try {
      return (db.prepare(`PRAGMA table_info(${JSON.stringify(table)})`).all() as { name: string }[]).map((r) => r.name);
    } finally {
      db.close();
    }
  }

  dbAll<T = Record<string, unknown>>(sql: string, ...params: (string | number | null)[]): T[] {
    const db = this.db();
    try {
      return db.prepare(sql).all(...params) as T[];
    } finally {
      db.close();
    }
  }

  dbRun(sql: string, ...params: (string | number | null)[]): { changes: number | bigint } {
    const db = this.db();
    try {
      return db.prepare(sql).run(...params);
    } finally {
      db.close();
    }
  }

  /** Raw bytes of the database (plus WAL) for "value is not stored in clear" checks. */
  dbBytes(): Buffer {
    const parts = [readFileSync(this.dbPath())];
    const wal = `${this.dbPath()}-wal`;
    if (existsSync(wal)) parts.push(readFileSync(wal));
    return Buffer.concat(parts);
  }

  dbContains(text: string): boolean {
    return this.dbBytes().includes(Buffer.from(text));
  }

  /** The users row for an email (columns as stored). */
  userByEmail(email: string): Record<string, unknown> | undefined {
    return this.dbAll('SELECT * FROM users WHERE lower(email) = lower(?)', email)[0];
  }

  userId(email: string): string | number {
    const row = this.userByEmail(email);
    if (!row) throw new Error(`no user ${email} in the database`);
    return row.id as string | number;
  }

  logPath(): string {
    return this.env.LOG_FILE ?? join(this.dataDir, 'app.log');
  }

  logText(): string {
    return existsSync(this.logPath()) ? readFileSync(this.logPath(), 'utf8') : '';
  }

  /** Parsed JSON log lines (throws on a line that is not valid JSON). */
  logLines(): Record<string, unknown>[] {
    return this.logText()
      .split('\n')
      .filter((l) => l.trim() !== '')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  outboxDir(): string {
    return join(this.dataDir, 'outbox');
  }

  /** Mail files written by the file mailer, newest last. */
  outbox(): { file: string; text: string }[] {
    const dir = this.outboxDir();
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((f) => !f.startsWith('.'))
      .map((f) => ({ file: join(dir, f), mtime: statSync(join(dir, f)).mtimeMs }))
      .sort((a, b) => a.mtime - b.mtime)
      .map((f) => ({ file: f.file, text: readFileSync(f.file, 'utf8') }));
  }

  async waitForOutbox(countAtLeast: number, timeoutMs = 5_000): Promise<{ file: string; text: string }[]> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const mails = this.outbox();
      if (mails.length >= countAtLeast || Date.now() > deadline) return mails;
      await sleep(150);
    }
  }

  // ---- Lifecycle -----------------------------------------------------------------------------------

  /** Kills the process group and removes a DATA_DIR the harness created, unless `keepDataDir` is set (restart scenarios). */
  async stop(opts: { keepDataDir?: boolean } = {}): Promise<void> {
    const child = this.child;
    if (child && child.exitCode === null && child.signalCode === null) {
      try {
        if (child.pid) process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, 3_000);
        child.once('exit', () => {
          clearTimeout(t);
          resolve();
        });
      });
    }
    if (this.ownsDataDir && !opts.keepDataDir) rmSync(this.dataDir, { recursive: true, force: true });
  }
}

function lowerKeys(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

// ---------------------------------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------------------------------

export const READY_PREFIX = '{"securevibe":"listening"';

/**
 * Starts `node --experimental-strip-types src/server.ts` in the template root and resolves once the
 * test-mode ready line has been printed (or /healthz answers, in production mode).
 */
export async function startApp(opts: StartOptions = {}): Promise<RunningApp> {
  const ownsDataDir = !opts.dataDir;
  const dataDir = opts.dataDir ?? mkdtempSync(join(tmpdir(), 'securevibe-test-'));
  const mode = opts.mode ?? 'test';
  const generated = generateEnv(dataDir);
  let port = 0;
  if (mode === 'production') {
    port = await freePort();
    generated.NODE_ENV = 'production';
    delete generated.SECUREVIBE_TEST_MODE;
    delete generated.SECUREVIBE_TEST_PASSWORD;
    delete generated.SECUREVIBE_TEST_TOTP_SEED;
    generated.EXAMPLE_FEATURE = '0';
    generated.PORT = String(port);
  }
  const env = childEnv({ ...generated, ...(opts.env ?? {}) });
  const output = { stdout: '', stderr: '' };

  const child = spawn(process.execPath, ['--experimental-strip-types', 'src/server.ts'], {
    cwd: templateRoot,
    env,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr!.on('data', (d: Buffer) => {
    output.stderr += d.toString();
  });

  const exited = new Promise<StartupFailure>((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal, stdout: output.stdout, stderr: output.stderr }));
  });
  let timer: NodeJS.Timeout | undefined;
  const timeout = (what: string) =>
    new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`app did not ${what} within 30 s\nstdout: ${output.stdout}\nstderr: ${output.stderr}`)),
        30_000,
      );
    });
  const failed = exited.then((f) => {
    throw new StartupError(f);
  });
  // After a successful start the process exits much later (on stop()); that rejection is expected.
  failed.catch(() => {});

  let readyPort: number;
  try {
    if (mode === 'test') {
      readyPort = await Promise.race([waitForReadyLine(child, output), failed, timeout('print the ready line')]);
    } else {
      child.stdout!.on('data', (d: Buffer) => {
        output.stdout += d.toString();
      });
      readyPort = await Promise.race([waitForHealth(port), failed, timeout('answer /healthz')]);
    }
  } catch (err) {
    clearTimeout(timer);
    if (opts.allowStartupFailure && err instanceof StartupError) {
      const app = new RunningApp(child, 0, dataDir, env, ownsDataDir, output);
      app.startupError = err.failure;
      return app;
    }
    await new RunningApp(child, 0, dataDir, env, ownsDataDir, output).stop();
    throw err;
  }
  clearTimeout(timer);
  return new RunningApp(child, readyPort, dataDir, env, ownsDataDir, output);
}

export class StartupError extends Error {
  readonly failure: StartupFailure;
  constructor(failure: StartupFailure) {
    super(
      `app exited during startup (code ${failure.code}, signal ${failure.signal})\nstdout: ${failure.stdout}\nstderr: ${failure.stderr}`,
    );
    this.failure = failure;
  }
}

function waitForReadyLine(child: ChildProcess, output: { stdout: string }): Promise<number> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    child.stdout!.on('data', (d: Buffer) => {
      const text = d.toString();
      output.stdout += text;
      buffer += text;
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith(READY_PREFIX)) {
          try {
            const info = JSON.parse(trimmed) as { port: number };
            resolve(info.port);
          } catch (e) {
            reject(new Error(`unparseable ready line: ${trimmed} (${String(e)})`));
          }
        }
      }
    });
  });
}

async function waitForHealth(port: number): Promise<number> {
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}${paths.healthz}`);
      await res.text();
      if (res.status === 200) return port;
    } catch {
      // not listening yet
    }
    await sleep(200);
  }
}

/**
 * Starts the app expecting it to refuse to start (e.g. weak secrets). Resolves with the exit information;
 * fails if the app is still running after `timeoutMs`.
 */
export async function expectStartupRefusal(env: Record<string, string | undefined>, timeoutMs = 15_000): Promise<StartupFailure> {
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-test-'));
  const merged = childEnv({ ...generateEnv(dataDir), ...env });
  const output = { stdout: '', stderr: '' };
  const child = spawn(process.execPath, ['--experimental-strip-types', 'src/server.ts'], {
    cwd: templateRoot,
    env: merged,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout!.on('data', (d: Buffer) => (output.stdout += d.toString()));
  child.stderr!.on('data', (d: Buffer) => (output.stderr += d.toString()));
  const result = await Promise.race([
    new Promise<StartupFailure>((resolve) =>
      child.once('exit', (code, signal) => resolve({ code, signal, stdout: output.stdout, stderr: output.stderr })),
    ),
    sleep(timeoutMs).then(() => null),
  ]);
  if (result === null) {
    try {
      if (child.pid) process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(`app kept running although it should have refused to start\nstdout: ${output.stdout}\nstderr: ${output.stderr}`);
  }
  rmSync(dataDir, { recursive: true, force: true });
  return result;
}

/**
 * Runs one of the template's scripts (`scripts/<name>.ts`) with the app's environment and returns its output.
 */
export function runScript(
  name: string,
  env: Record<string, string>,
  opts: { args?: string[]; cwd?: string; timeoutMs?: number } = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', join(templateRoot, 'scripts', `${name}.ts`), ...(opts.args ?? [])], {
      cwd: opts.cwd ?? templateRoot,
      env: childEnv(env),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    const t = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`script ${name} timed out\nstdout: ${stdout}\nstderr: ${stderr}`));
    }, opts.timeoutMs ?? 60_000);
    child.once('exit', (code) => {
      clearTimeout(t);
      resolve({ code, stdout, stderr });
    });
    child.once('error', reject);
  });
}

/**
 * Runs a TypeScript snippet in a fresh child process with the given environment and returns its stdout.
 * Used to exercise template modules (e.g. src/lib/http-client.ts) whose config is read once at import.
 */
export async function runSnippet(code: string, env: Record<string, string>, timeoutMs = 30_000): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const { writeFileSync } = await import('node:fs');
  const dir = mkdtempSync(join(tmpdir(), 'securevibe-snippet-'));
  const file = join(dir, 'snippet.ts');
  writeFileSync(file, code);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', file], {
      cwd: templateRoot,
      env: childEnv(env),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    const t = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`snippet timed out\nstdout: ${stdout}\nstderr: ${stderr}`));
    }, timeoutMs);
    child.once('exit', (exitCode) => {
      clearTimeout(t);
      rmSync(dir, { recursive: true, force: true });
      resolve({ code: exitCode, stdout, stderr });
    });
    child.once('error', reject);
  });
}

/** Absolute path of a template module for `import()` inside snippets. */
export function moduleUrl(relative: string): string {
  return new URL(relative, `file://${templateRoot}/`).href;
}

/** Fills express-style `:param` placeholders. */
export function fillPath(path: string, values: Record<string, string | number>, fallback = 'does-not-exist'): string {
  return path.replace(/:([A-Za-z_][A-Za-z0-9_]*)\??/g, (_m, name: string) => encodeURIComponent(String(values[name] ?? fallback)));
}
