/**
 * App preview: runs a built app on this computer so the owner can click around in it.
 *
 *  - Throw-away data: a fresh data folder and fresh secrets every time; the app's own data and `.env` values that
 *    matter (mail, outbound calls, AI) are overridden, so a preview never sends email, never calls out and never
 *    spends AI credit.
 *  - A preview administrator with a one-time password is created for each start.
 *  - The app runs under the same sandbox as the build checks, listens on 127.0.0.1 only, and is opened as
 *    http://localhost:<port>. SecureVibe only accepts its own sign-in on 127.0.0.1, so its session cookie is never
 *    valid on the host the preview uses.
 *  - A preview stops after an hour, when it is stopped, when the app is rebuilt or deleted, and when SecureVibe exits.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import type { BuildSpec } from '@shared/design.js';
import { freePort, generateAppEnv, probeHealth, resolveEntry } from '../scanners/dast/harness.js';
import { removeDir, spawnSandboxed, type SandboxedProcess } from '../pipeline/process.js';
import type { ProjectStore } from '../store/index.js';

export const PREVIEW_MAX_MS = 60 * 60_000;
const START_TIMEOUT_MS = 45_000;

export interface PreviewInfo {
  running: boolean;
  url?: string;
  email?: string;
  password?: string;
  startedAt?: string;
  stopsAt?: string;
  /** What the preview changes compared with the real app. */
  differences: string[];
}

interface ActivePreview {
  proc: SandboxedProcess;
  dataDir: string;
  port: number;
  email: string;
  password: string;
  /** The one-time value in the preview's sign-in link (see PREVIEW_SIGNIN_TOKEN in the app template). */
  signInToken: string;
  startedAt: number;
  timer: NodeJS.Timeout;
}

export class PreviewError extends Error {
  /** The app's own output, for the server log (never shown in the page). */
  constructor(
    message: string,
    readonly detail = '',
  ) {
    super(message);
  }
}

const DIFFERENCES = [
  'It starts empty each time, with its own throw-away data. Nothing you do in the preview reaches your real app.',
  'Emails are not sent, the app does not call other services, and its AI features are switched off (no credit is used).',
  'The link signs you in as a preview administrator, and the app says so on every page. Your real app asks for a password and, when you chose it, a code from an authenticator app.',
];

/** Polls the app's /healthz (through the runtime scanner's probe) until it answers, exits or the deadline passes. */
async function waitForHealth(port: number, deadline: number, proc: SandboxedProcess): Promise<boolean> {
  while (Date.now() < deadline) {
    if (proc.child.exitCode !== null || proc.child.signalCode !== null) return false;
    if (await probeHealth(port, false)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

/** Every manager in this process, so one exit hook stops every preview when SecureVibe stops. */
const MANAGERS = new Set<PreviewManager>();
let exitHookInstalled = false;

export class PreviewManager {
  private readonly active = new Map<string, ActivePreview>();
  private readonly starting = new Set<string>();

  constructor(private readonly store: ProjectStore) {
    MANAGERS.add(this);
    if (!exitHookInstalled) {
      exitHookInstalled = true;
      process.once('exit', () => {
        for (const m of MANAGERS) m.stopAll();
      });
    }
  }

  stopAll(): void {
    for (const id of [...this.active.keys()]) this.stop(id);
  }

  info(projectId: string): PreviewInfo {
    const p = this.active.get(projectId);
    if (!p) return { running: false, differences: DIFFERENCES };
    return {
      running: true,
      // One click: the app signs the visitor in as its administrator (only a preview accepts this link).
      url: `http://localhost:${p.port}/preview-signin?t=${encodeURIComponent(p.signInToken)}`,
      email: p.email,
      password: p.password,
      startedAt: new Date(p.startedAt).toISOString(),
      stopsAt: new Date(p.startedAt + PREVIEW_MAX_MS).toISOString(),
      differences: DIFFERENCES,
    };
  }

  isRunning(projectId: string): boolean {
    return this.active.has(projectId);
  }

  async start(projectId: string, buildSpec: BuildSpec): Promise<PreviewInfo> {
    if (this.active.has(projectId)) return this.info(projectId);
    if (this.starting.has(projectId)) throw new PreviewError('The preview is already starting. Wait a moment.');
    const paths = this.store.paths(projectId);
    // Real paths: the sandbox's file rules must name the folders as the operating system resolves them.
    const appDir = existsSync(paths.appDir) ? realpathSync(paths.appDir) : paths.appDir;
    const entry = resolveEntry(appDir);
    if (!entry || !existsSync(join(appDir, 'node_modules'))) {
      throw new PreviewError('This app has not been built completely yet, so it cannot be previewed. Build it first.');
    }

    this.starting.add(projectId);
    let dataDir = join(paths.dir, 'tmp', `preview-${randomBytes(4).toString('hex')}`);
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    dataDir = realpathSync(dataDir);
    try {
      const port = await freePort();
      const signInToken = randomBytes(32).toString('base64url');
      const env: Record<string, string> = {
        ...generateAppEnv('production', buildSpec, dataDir, port),
        NODE_ENV: 'production',
        TLS_MODE: 'off',
        TRUST_PROXY_HOPS: '0',
        BIND_LAN: '0',
        LOG_LEVEL: 'warn',
        // Values the app's own .env must not bring into a preview.
        SMTP_URL: '',
        OUTBOUND_ALLOWED_HOSTS: '',
        AI_ENABLED: '0',
        ANTHROPIC_API_KEY: '',
        ADMIN_MFA_REQUIRED: '0',
        ADMIN_EMAIL: 'preview-admin@example.com',
        PREVIEW_SIGNIN_TOKEN: signInToken,
      };
      const common = { cwd: appDir, env, projectDir: realpathSync(paths.dir), pidDir: dataDir, permission: { read: [appDir], write: [dataDir] } };

      // The administrator is created from the preview data folder, which is where FIRST-LOGIN.txt is written.
      const admin = spawnSandboxed({
        ...common,
        cmd: 'node',
        args: ['--experimental-strip-types', join(appDir, 'scripts', 'bootstrap-admin.ts'), '--email', 'preview-admin@example.com', '--no-force-change'],
        cwd: dataDir,
        permission: { read: [appDir, dataDir], write: [dataDir] },
        timeoutMs: 60_000,
      });
      const adminResult = await admin.wait();
      const loginFile = join(dataDir, 'FIRST-LOGIN.txt');
      const password = existsSync(loginFile) ? /One-time password:\s*(\S+)/.exec(readFileSync(loginFile, 'utf8'))?.[1] : undefined;
      if (adminResult.code !== 0 || !password) {
        throw new PreviewError('The preview could not create its sign-in account. Try building the app again.', `${adminResult.stderr}\n${adminResult.stdout}`.slice(-2000));
      }

      const proc = spawnSandboxed({ ...common, cmd: 'node', args: entry, timeoutMs: PREVIEW_MAX_MS + 60_000, maxOutputBytes: 1024 * 1024 });
      const ready = await waitForHealth(port, Date.now() + START_TIMEOUT_MS, proc);
      if (!ready) {
        proc.kill();
        const result = await proc.wait();
        throw new PreviewError('The app did not start. The build results may show why; building it again often helps.', `${result.stderr}\n${result.stdout}`.slice(-2000));
      }

      const timer = setTimeout(() => this.stop(projectId), PREVIEW_MAX_MS);
      timer.unref();
      const entryRecord: ActivePreview = { proc, dataDir, port, email: 'preview-admin@example.com', password, signInToken, startedAt: Date.now(), timer };
      this.active.set(projectId, entryRecord);
      // If the app stops by itself, forget it and clean up.
      void proc.wait().then(() => {
        if (this.active.get(projectId) === entryRecord) this.stop(projectId);
      });
      return this.info(projectId);
    } catch (err) {
      removeDir(dataDir);
      throw err;
    } finally {
      this.starting.delete(projectId);
    }
  }

  stop(projectId: string): boolean {
    const p = this.active.get(projectId);
    if (!p) return false;
    this.active.delete(projectId);
    clearTimeout(p.timer);
    p.proc.kill();
    void p.proc.wait().finally(() => removeDir(p.dataDir));
    return true;
  }
}
