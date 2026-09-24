/**
 * Starts the generated app for the runtime scanner (CONTRACTS §2, §1.16, §9.3): fresh secrets, a throw-away
 * DATA_DIR, the permission model, and ready detection. Three kinds of start exist:
 *  - `test`: NODE_ENV=test + SECUREVIBE_TEST_MODE=1 (seeded users, /__securevibe endpoints, one JSON ready line);
 *  - `production`: production mode behind a pretend TLS proxy (TLS_MODE=proxy, TRUST_PROXY_HOPS=1) — no ready
 *    line, so a free port is chosen up front and /healthz is polled;
 *  - `selfsigned`: production mode with the app's own certificate (only when certs/ exists).
 */
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createServer } from 'node:net';
import { join } from 'node:path';
import type { BuildSpec } from '@shared/design.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import { removeDir, spawnSandboxed, type SandboxedProcess } from '../../pipeline/process.js';
import { randomTotpSeed } from './totp.js';
import type { AppInstance, ProbePhase } from './types.js';

export const READY_TIMEOUT_MS = 30_000;
export const DEFAULT_READY_PREFIX = '{"securevibe":"listening"';

/** Small limits so upload probes stay fast; the contract lets the environment override them. */
export const PROBE_UPLOAD_MAX_BYTES = 65_536;
export const PROBE_UPLOAD_QUOTA_BYTES = 3_072;
export const PROBE_AI_MAX_INPUT_CHARS = 1_000;

export class AppStartError extends Error {
  constructor(
    message: string,
    readonly stdout: string,
    readonly stderr: string,
    readonly exitCode: number | null,
  ) {
    super(message);
    this.name = 'AppStartError';
  }
}

export interface StartAppOptions {
  appDir: string;
  projectDir: string;
  runId: string;
  phase: ProbePhase;
  buildSpec: BuildSpec;
  testMode?: TemplateManifest['testMode'];
  /** Node arguments that start the app (default: derived from the app folder, see `resolveEntry`). */
  entry?: string[];
  extraEnv?: Record<string, string>;
  /** Extra read-only paths for the permission model (node_modules outside the app folder, for example). */
  extraReadPaths?: string[];
  /** Skip the permission model (tests of the harness itself). Default: sandboxed. */
  sandbox?: boolean;
  readyTimeoutMs?: number;
  log?: (msg: string) => void;
  abort?: AbortSignal;
}

export function b64(bytes = 32): string {
  return randomBytes(bytes).toString('base64');
}

export function randomPassword(length = 24): string {
  return randomBytes(length).toString('base64url').slice(0, length);
}

/** How to start the app: the contract's `node --experimental-strip-types src/server.ts`, or a plain JS entry. */
export function resolveEntry(appDir: string): string[] | undefined {
  if (existsSync(join(appDir, 'src', 'server.ts'))) return ['--experimental-strip-types', 'src/server.ts'];
  for (const candidate of ['src/server.js', 'src/server.mjs', 'server.js', 'server.mjs', 'index.js']) {
    if (existsSync(join(appDir, candidate))) return [candidate];
  }
  return undefined;
}

export function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolvePort(port));
    });
    srv.on('error', reject);
  });
}

/** The environment for one start (CONTRACTS §1.3 names). Secrets are fresh every time and never persisted. */
export function generateAppEnv(
  phase: ProbePhase,
  buildSpec: BuildSpec,
  dataDir: string,
  port: number,
  testMode?: TemplateManifest['testMode'],
): Record<string, string> {
  const base: Record<string, string> = {
    PORT: String(port),
    DATA_DIR: dataDir,
    SESSION_SECRET: b64(32),
    FIELD_KEYS: `1:${b64(32)}`,
    ACTIVE_FIELD_KEY: '1',
    TOKEN_HMAC_KEY: b64(32),
    LOG_LEVEL: 'info',
    LOG_FILE: join(dataDir, 'app.log'),
    OUTBOUND_ALLOWED_HOSTS: '',
    BIND_LAN: '0',
    SESSION_IDLE_MINUTES: String(buildSpec.sessionPolicy.idleMinutes),
    SESSION_ABSOLUTE_HOURS: String(buildSpec.sessionPolicy.absoluteHours),
    SESSION_MAX_CONCURRENT: String(buildSpec.sessionPolicy.maxConcurrent),
    ADMIN_MFA_REQUIRED: buildSpec.features.adminMfa ? '1' : '0',
    USER_MFA_AVAILABLE: buildSpec.features.userMfa ? '1' : '0',
    AI_ENABLED: buildSpec.features.ai ? '1' : '0',
  };
  if (phase === 'test') {
    const flag = testMode?.envFlag ?? 'SECUREVIBE_TEST_MODE';
    return {
      ...base,
      NODE_ENV: 'test',
      [flag]: '1',
      TLS_MODE: 'off',
      TRUST_PROXY_HOPS: '0',
      SECUREVIBE_TEST_PASSWORD: randomPassword(24),
      SECUREVIBE_TEST_TOTP_SEED: randomTotpSeed(),
      EXAMPLE_FEATURE: '1',
      UPLOAD_MAX_BYTES: String(PROBE_UPLOAD_MAX_BYTES),
      UPLOAD_USER_QUOTA_BYTES: String(PROBE_UPLOAD_QUOTA_BYTES),
      AI_MAX_INPUT_CHARS: String(PROBE_AI_MAX_INPUT_CHARS),
    };
  }
  if (phase === 'selfsigned') {
    return { ...base, NODE_ENV: 'production', TLS_MODE: 'selfsigned', TRUST_PROXY_HOPS: '0', EXAMPLE_FEATURE: '0' };
  }
  return { ...base, NODE_ENV: 'production', TLS_MODE: 'proxy', TRUST_PROXY_HOPS: '1', EXAMPLE_FEATURE: '0' };
}

function parseReadyLine(line: string): { port: number; pid?: number; tlsMode?: string } | undefined {
  try {
    const parsed = JSON.parse(line.trim()) as { securevibe?: string; port?: number; pid?: number; tlsMode?: string };
    if (parsed.securevibe === 'listening' && typeof parsed.port === 'number') {
      return { port: parsed.port, pid: parsed.pid, tlsMode: parsed.tlsMode };
    }
  } catch {
    // not JSON
  }
  return undefined;
}

export function probeHealth(port: number, tls: boolean): Promise<boolean> {
  return new Promise((resolveHealth) => {
    const mod = tls ? https : http;
    const req = mod.request(
      // The app under test was started by SecureVibe on this computer with a self-signed certificate; the
      // certificate is not what is being checked here, only whether the app answers. Never used for anything else.
      { host: '127.0.0.1', port, path: '/healthz', method: 'GET', timeout: 2_000, rejectUnauthorized: false } as http.RequestOptions,
      (res) => {
        res.resume();
        resolveHealth(res.statusCode !== undefined && res.statusCode < 500);
      },
    );
    req.on('error', () => resolveHealth(false));
    req.on('timeout', () => {
      req.destroy();
      resolveHealth(false);
    });
    req.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Starts the app and waits until it is ready (≤ 30 s). Throws `AppStartError` with the captured output when the
 * process exits early, the ready line never comes, or the port is unreachable.
 */
export async function startApp(opts: StartAppOptions): Promise<AppInstance> {
  const log = opts.log ?? (() => {});
  const entry = opts.entry ?? resolveEntry(opts.appDir);
  if (!entry) throw new AppStartError('No start file found (expected src/server.ts).', '', '', null);

  const tmpRoot = join(opts.projectDir, 'tmp');
  mkdirSync(tmpRoot, { recursive: true });
  const dataDir = join(tmpRoot, `dast-${opts.phase}-${randomBytes(4).toString('hex')}`);
  mkdirSync(dataDir, { recursive: true });

  const port = opts.phase === 'test' ? 0 : await freePort();
  const env = { ...generateAppEnv(opts.phase, opts.buildSpec, dataDir, port, opts.testMode), ...(opts.extraEnv ?? {}) };
  const readyPrefix = opts.testMode?.readyLinePrefix ?? DEFAULT_READY_PREFIX;

  let stdoutBuffer = '';
  let readyPort: number | undefined;
  let readyTls: string | undefined;
  let resolveReady: (() => void) | undefined;
  const readyPromise = new Promise<void>((r) => {
    resolveReady = r;
  });

  const proc: SandboxedProcess = spawnSandboxed({
    cmd: 'node',
    args: entry,
    cwd: opts.appDir,
    env,
    projectDir: opts.projectDir,
    runId: opts.runId,
    // The app keeps running until we stop it; the DAST stage has its own overall limit.
    timeoutMs: 30 * 60_000,
    maxOutputBytes: 4 * 1024 * 1024,
    permission: opts.sandbox === false ? undefined : { read: [opts.appDir, ...(opts.extraReadPaths ?? [])], write: [dataDir] },
    abort: opts.abort,
    onStdout: (chunk) => {
      if (readyPort !== undefined) return;
      stdoutBuffer += chunk;
      let idx = stdoutBuffer.indexOf('\n');
      while (idx >= 0) {
        const line = stdoutBuffer.slice(0, idx);
        stdoutBuffer = stdoutBuffer.slice(idx + 1);
        if (line.trimStart().startsWith(readyPrefix)) {
          const parsed = parseReadyLine(line);
          if (parsed) {
            readyPort = parsed.port;
            readyTls = parsed.tlsMode;
            resolveReady?.();
            return;
          }
        }
        idx = stdoutBuffer.indexOf('\n');
      }
    },
  });
  for (const w of proc.warnings) log(`[dast] ${w}`);

  const exited = proc.wait();
  const deadline = Date.now() + (opts.readyTimeoutMs ?? READY_TIMEOUT_MS);
  const tls = opts.phase === 'selfsigned';

  let ready = false;
  let earlyExit = false;
  if (opts.phase === 'test') {
    const timeout = sleep(Math.max(0, deadline - Date.now())).then(() => 'timeout' as const);
    const outcome = await Promise.race([readyPromise.then(() => 'ready' as const), exited.then(() => 'exit' as const), timeout]);
    ready = outcome === 'ready';
    earlyExit = outcome === 'exit';
  } else {
    while (Date.now() < deadline) {
      if (proc.child.exitCode !== null || proc.child.signalCode !== null) {
        earlyExit = true;
        break;
      }
      if (await probeHealth(port, tls)) {
        ready = true;
        readyPort = port;
        break;
      }
      await sleep(250);
    }
  }

  if (!ready) {
    proc.kill();
    const result = await exited;
    removeDir(dataDir);
    const why = earlyExit
      ? `The app exited before it was ready (exit code ${result.code ?? 'unknown'}).`
      : 'The app did not report that it was listening within 30 seconds.';
    throw new AppStartError(why, result.stdout, result.stderr, result.code);
  }

  const finalPort = readyPort ?? port;
  const scheme = tls ? 'https' : 'http';
  const instance: AppInstance = {
    phase: opts.phase,
    baseUrl: `${scheme}://127.0.0.1:${finalPort}`,
    port: finalPort,
    pid: proc.pid,
    dataDir,
    env,
    tlsMode: (env['TLS_MODE'] as AppInstance['tlsMode']) ?? (readyTls as AppInstance['tlsMode']) ?? 'off',
    sandboxMode: proc.sandboxMode,
    output: () => ({ stdout: proc.stdout, stderr: proc.stderr }),
    stop: async () => {
      proc.kill();
      await exited;
      removeDir(dataDir);
    },
  };
  log(`[dast] app ready in ${opts.phase} mode on port ${finalPort} (${proc.sandboxMode})`);
  return instance;
}
