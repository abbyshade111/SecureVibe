/**
 * Process sandbox (CONTRACTS §9.3): every child process SecureVibe starts for a generated app — the app itself
 * under the runtime scanner, its test suite, npm, external scanners — goes through here.
 *
 *  - `node` runs as `process.execPath` under Node's permission model (`--permission --allow-fs-read/--allow-fs-write`)
 *    when the caller asks for it. Whether the running Node accepts the flag is detected once at runtime; when it
 *    does not, the process runs unsandboxed and the result carries a warning so the reports can say so.
 *  - `npm` runs as `node <npm-cli.js>` resolved from the Node installation (fallback: `npm` on PATH, never a shell).
 *  - Children start in their own process group so timeouts, aborts and stale-process sweeps can kill the whole
 *    tree with one signal.
 *  - The environment is an allow-list: PATH, a project-local HOME and TMPDIR, NODE_ENV and the app variables the
 *    caller passes. Nothing from SecureVibe's own environment (API keys, SECUREVIBE_* settings) reaches the child.
 *  - Output is capped per stream and marked `[truncated]`.
 *  - A pid file is written for the lifetime of the child so a later start can sweep processes an earlier crash left.
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { detectNetworkFence } from './net-fence.js';
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, delimiter, dirname, join, resolve } from 'node:path';

export type SandboxMode = 'node-permission-model+loopback-only' | 'node-permission-model' | 'none';

export interface PermissionSpec {
  /** Directories/files the child may read (the cwd and node_modules of the app belong here). */
  read: string[];
  /** Directories the child may write (throw-away DATA_DIR, tmp). Created when missing. */
  write: string[];
  /** Needed for the test runner (node --test spawns workers) and for apps that must spawn children. */
  allowChildProcess?: boolean;
  allowWorker?: boolean;
  /** Grant network access (default true: the app under test must listen; Node has no per-host filter). */
  allowNet?: boolean;
  /**
   * 'loopback-only' (default): the OS network fence (pipeline/net-fence.ts) keeps the process to 127.0.0.1, so
   * nothing leaves the computer. 'any': no fence, for an app that genuinely has to reach outside hosts.
   */
  network?: 'loopback-only' | 'any';
}

export interface SpawnSandboxedOptions {
  cmd: 'node' | 'npm';
  args: string[];
  cwd: string;
  /** App variables for the child. `undefined` values are skipped. */
  env?: Record<string, string | undefined>;
  /** Wall-clock limit; the process group is killed when it is reached. Default 2 minutes. */
  timeoutMs?: number;
  /** Cap per stream (stdout and stderr each). Default 2 MiB. */
  maxOutputBytes?: number;
  /** When given, `node` runs under the permission model with these paths. Ignored for `npm`. */
  permission?: PermissionSpec;
  /** SecureVibe project folder: HOME and TMPDIR for the child live under it, and so does the pid file. */
  projectDir?: string;
  /** Pipeline run id: pid files go to `<projectDir>/pipeline/<runId>/`. */
  runId?: string;
  /** Explicit pid-file directory (overrides projectDir/runId). */
  pidDir?: string;
  abort?: AbortSignal;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
  /** Names of parent environment variables to pass through in addition to PATH (tests use npm_config_registry). */
  passThroughEnv?: string[];
}

export interface ProcessResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  aborted: boolean;
  truncated: boolean;
  sandboxMode: SandboxMode;
  warnings: string[];
  durationMs: number;
  /** The command line that ran (for run logs). */
  command: string;
  pid?: number;
}

export interface SandboxedProcess {
  readonly pid: number | undefined;
  readonly child: ChildProcess;
  readonly sandboxMode: SandboxMode;
  readonly warnings: string[];
  readonly command: string;
  /** Output captured so far (capped). */
  readonly stdout: string;
  readonly stderr: string;
  /** Resolves when the process has exited, including after a timeout/abort kill. */
  wait(): Promise<ProcessResult>;
  /** Kills the whole process group (SIGKILL by default). */
  kill(signal?: NodeJS.Signals): void;
}

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
export const TRUNCATED_MARKER = '\n[truncated]\n';

export const SANDBOX_NOTE: Record<SandboxMode, string> = {
  'node-permission-model+loopback-only':
    "Generated code runs with the user's OS privileges under Node's permission model (file system restricted to the project folder) and behind the operating system's network fence: it can talk to this computer only, nothing outside.",
  'node-permission-model':
    "Generated code runs with the user's OS privileges under Node's permission model (file system restricted to the project folder); network access is not restricted.",
  none: "Generated code ran with the user's OS privileges and no file-system restriction because this Node version does not support the permission model; network access is not restricted.",
};

// ---------------------------------------------------------------------------------------------------
// Permission model detection
// ---------------------------------------------------------------------------------------------------

let permissionSupport: boolean | undefined;

/** Real path for permission flags: Node compares real paths, and /tmp on macOS is a symlink to /private/tmp. */
export function realPathFor(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return resolve(p);
  }
}

/** True when the running Node accepts `--permission` (checked once per process, never on the network). */
export function detectPermissionSupport(): boolean {
  if (permissionSupport !== undefined) return permissionSupport;
  const probeDir = realPathFor(tmpdir());
  const result = spawnSync(process.execPath, ['--permission', `--allow-fs-read=${probeDir}`, '-e', 'process.exit(0)'], {
    timeout: 15_000,
    env: minimalParentEnv(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  permissionSupport = result.status === 0;
  return permissionSupport;
}

/** Tests only: forget the cached detection result. */
export function resetPermissionDetection(value?: boolean): void {
  permissionSupport = value;
}

/** What a build's provenance says about how generated code was run on this computer. */
export function describeSandbox(): { mode: SandboxMode; note: string } {
  const mode: SandboxMode = !detectPermissionSupport() ? 'none' : detectNetworkFence().kind === 'none' ? 'node-permission-model' : 'node-permission-model+loopback-only';
  return { mode, note: SANDBOX_NOTE[mode] };
}

// ---------------------------------------------------------------------------------------------------
// npm resolution
// ---------------------------------------------------------------------------------------------------

export type NpmInvocation = { kind: 'node-script'; script: string } | { kind: 'path'; file: string };

function findOnPath(name: string): string | undefined {
  const dirs = (process.env['PATH'] ?? '').split(delimiter).filter(Boolean);
  const names = process.platform === 'win32' ? [`${name}.cmd`, `${name}.exe`, name] : [name];
  for (const dir of dirs) {
    for (const n of names) {
      const candidate = join(dir, n);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

/**
 * Finds npm's CLI script next to the running Node so npm runs as `node npm-cli.js` (no shell, same Node).
 * Layouts: <prefix>/lib/node_modules/npm (nvm, official installers), <prefix>/libexec/lib/node_modules/npm
 * (Homebrew), <prefix>/node_modules/npm (Windows). Falls back to the `npm` on PATH when it is itself the script,
 * and finally to running `npm` from PATH.
 */
export function resolveNpm(): NpmInvocation {
  const execDir = dirname(process.execPath);
  const candidates = [
    join(execDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(execDir, '..', 'libexec', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(execDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  for (const c of candidates) if (existsSync(c)) return { kind: 'node-script', script: realPathFor(c) };
  const onPath = findOnPath('npm');
  if (onPath) {
    const real = realPathFor(onPath);
    if (basename(real) === 'npm-cli.js') return { kind: 'node-script', script: real };
    return { kind: 'path', file: onPath };
  }
  return { kind: 'path', file: 'npm' };
}

// ---------------------------------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------------------------------

function minimalParentEnv(extraNames: string[] = []): Record<string, string> {
  const env: Record<string, string> = {};
  const names = ['PATH', ...(process.platform === 'win32' ? ['SYSTEMROOT', 'SystemRoot', 'COMSPEC', 'PATHEXT'] : []), ...extraNames];
  for (const name of names) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  return env;
}

export interface ChildEnvOptions {
  projectDir?: string;
  cwd: string;
  env?: Record<string, string | undefined>;
  passThroughEnv?: string[];
  cmd: 'node' | 'npm' | 'other';
}

/** Builds the allow-listed environment and creates the project-local HOME and TMPDIR. */
export function buildChildEnv(opts: ChildEnvOptions): { env: Record<string, string>; home: string; tmp: string } {
  const base = opts.projectDir ?? opts.cwd;
  const home = join(base, 'home');
  const tmp = join(base, 'tmp');
  mkdirSync(home, { recursive: true });
  mkdirSync(tmp, { recursive: true });
  const env = minimalParentEnv(opts.passThroughEnv);
  env['HOME'] = home;
  env['USERPROFILE'] = home;
  env['TMPDIR'] = tmp;
  env['TMP'] = tmp;
  env['TEMP'] = tmp;
  env['NO_COLOR'] = '1';
  env['FORCE_COLOR'] = '0';
  if (opts.cmd === 'npm') {
    env['npm_config_cache'] = join(tmp, 'npm-cache');
    env['npm_config_update_notifier'] = 'false';
    env['npm_config_fund'] = 'false';
    env['npm_config_progress'] = 'false';
    env['npm_config_color'] = 'false';
  }
  for (const [key, value] of Object.entries(opts.env ?? {})) {
    if (value === undefined) continue;
    // The caller's own variables are trusted; SecureVibe's credentials never come from here.
    if (/^ANTHROPIC_/i.test(key)) continue;
    env[key] = value;
  }
  return { env, home, tmp };
}

// ---------------------------------------------------------------------------------------------------
// Pid files and process groups
// ---------------------------------------------------------------------------------------------------

interface PidRecord {
  pid: number;
  command: string;
  startedAt: string;
}

export function killProcessGroup(pid: number, signal: NodeJS.Signals = 'SIGKILL'): boolean {
  if (process.platform === 'win32') {
    const r = spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', timeout: 10_000 });
    return r.status === 0;
  }
  let killed = false;
  try {
    process.kill(-pid, signal);
    killed = true;
  } catch {
    // The group may already be gone; fall back to the process itself.
  }
  try {
    process.kill(pid, signal);
    killed = true;
  } catch {
    // already exited
  }
  return killed;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function commandNameOf(pid: number): string {
  if (process.platform === 'win32') return 'node';
  const r = spawnSync('ps', ['-o', 'comm=', '-p', String(pid)], { encoding: 'utf8', timeout: 5_000 });
  return (r.stdout ?? '').trim();
}

/**
 * Kills processes recorded in `dir/*.pid` that are still alive (only when they still look like node/npm, so a
 * reused pid never hits an unrelated program) and removes the files. Call at startup and before a new run.
 */
export function sweepStalePids(dir: string): { pid: number; killed: boolean; file: string }[] {
  const out: { pid: number; killed: boolean; file: string }[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (!name.endsWith('.pid')) continue;
    const file = join(dir, name);
    let record: PidRecord | undefined;
    try {
      record = JSON.parse(readFileSync(file, 'utf8')) as PidRecord;
    } catch {
      record = undefined;
    }
    let killed = false;
    if (record && Number.isInteger(record.pid) && record.pid > 1 && isAlive(record.pid)) {
      const comm = commandNameOf(record.pid).toLowerCase();
      if (comm === '' || /node|npm/.test(comm)) killed = killProcessGroup(record.pid);
    }
    try {
      unlinkSync(file);
    } catch {
      // nothing to do
    }
    out.push({ pid: record?.pid ?? -1, killed, file });
  }
  return out;
}

function writePidFile(dir: string, record: PidRecord): string | undefined {
  try {
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${record.pid}.pid`);
    writeFileSync(file, JSON.stringify(record));
    return file;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------------------------------

class OutputBuffer {
  private chunks: string[] = [];
  private size = 0;
  truncated = false;

  constructor(private readonly max: number) {}

  push(chunk: string): void {
    if (this.truncated) return;
    if (this.size + chunk.length > this.max) {
      const room = Math.max(0, this.max - this.size);
      if (room > 0) this.chunks.push(chunk.slice(0, room));
      this.chunks.push(TRUNCATED_MARKER);
      this.size = this.max;
      this.truncated = true;
      return;
    }
    this.chunks.push(chunk);
    this.size += chunk.length;
  }

  toString(): string {
    return this.chunks.join('');
  }
}

export interface SpawnCommandOptions extends Omit<SpawnSandboxedOptions, 'cmd' | 'args' | 'permission'> {
  sandboxMode?: SandboxMode;
  warnings?: string[];
  envKind?: 'node' | 'npm' | 'other';
}

/** Spawns any executable with the sandbox conventions (no shell, allow-listed env, group kill, caps, pid file). */
export function spawnCommand(file: string, args: string[], opts: SpawnCommandOptions): SandboxedProcess {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutput = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const warnings = [...(opts.warnings ?? [])];
  const sandboxMode = opts.sandboxMode ?? 'none';
  const { env } = buildChildEnv({
    projectDir: opts.projectDir,
    cwd: opts.cwd,
    env: opts.env,
    passThroughEnv: opts.passThroughEnv,
    cmd: opts.envKind ?? 'other',
  });
  const command = [file, ...args].join(' ');
  const startedAt = Date.now();

  const child = spawn(file, args, {
    cwd: opts.cwd,
    env,
    detached: process.platform !== 'win32',
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  const stdout = new OutputBuffer(maxOutput);
  const stderr = new OutputBuffer(maxOutput);
  let timedOut = false;
  let aborted = false;
  let finished = false;
  let pidFile: string | undefined;

  const pidDir = opts.pidDir ?? (opts.projectDir ? join(opts.projectDir, 'pipeline', opts.runId ?? 'current') : undefined);
  if (child.pid && pidDir) {
    pidFile = writePidFile(pidDir, { pid: child.pid, command, startedAt: new Date(startedAt).toISOString() });
  }

  child.stdout?.setEncoding('utf8');
  child.stderr?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => {
    stdout.push(chunk);
    opts.onStdout?.(chunk);
  });
  child.stderr?.on('data', (chunk: string) => {
    stderr.push(chunk);
    opts.onStderr?.(chunk);
  });

  const kill = (signal: NodeJS.Signals = 'SIGKILL'): void => {
    if (finished || !child.pid) return;
    killProcessGroup(child.pid, signal);
  };

  const timer = setTimeout(() => {
    timedOut = true;
    warnings.push(`The process was stopped after ${Math.round(timeoutMs / 1000)} seconds (time limit).`);
    kill();
  }, timeoutMs);
  timer.unref();

  const onAbort = (): void => {
    aborted = true;
    kill();
  };
  if (opts.abort) {
    if (opts.abort.aborted) onAbort();
    else opts.abort.addEventListener('abort', onAbort, { once: true });
  }

  let spawnError: Error | undefined;
  const done = new Promise<ProcessResult>((resolveDone) => {
    let settled = false;
    const settle = (code: number | null, signal: NodeJS.Signals | null): void => {
      if (settled) return;
      settled = true;
      finished = true;
      clearTimeout(timer);
      opts.abort?.removeEventListener('abort', onAbort);
      if (pidFile) {
        try {
          unlinkSync(pidFile);
        } catch {
          // already removed
        }
      }
      if (spawnError) {
        warnings.push(`The process could not be started: ${spawnError.message}`);
        stderr.push(`${spawnError.message}\n`);
      }
      resolveDone({
        code,
        signal,
        stdout: stdout.toString(),
        stderr: stderr.toString(),
        timedOut,
        aborted,
        truncated: stdout.truncated || stderr.truncated,
        sandboxMode,
        warnings,
        durationMs: Date.now() - startedAt,
        command,
        pid: child.pid,
      });
    };
    child.on('error', (err) => {
      spawnError = err;
      // 'close' still fires after a spawn error; settle now so callers never hang on a missing binary.
      settle(child.exitCode ?? -1, child.signalCode ?? null);
    });
    child.on('exit', (code, signal) => {
      // Grandchildren may keep the stdio pipes open after a group kill; do not wait forever for 'close'.
      const fallback = setTimeout(() => settle(code, signal), 1_000);
      fallback.unref();
    });
    child.on('close', (code, signal) => settle(code, signal));
  });

  return {
    get pid() {
      return child.pid;
    },
    child,
    sandboxMode,
    warnings,
    command,
    get stdout() {
      return stdout.toString();
    },
    get stderr() {
      return stderr.toString();
    },
    wait: () => done,
    kill,
  };
}

/**
 * Node compares permission paths literally, so a folder reached through a symlink (on macOS every path under
 * /tmp and $TMPDIR) must be listed under both its own name and its real name, or the child is denied access to
 * the very folder it was given.
 */
function bothForms(paths: string[]): string[] {
  const out = new Set<string>();
  for (const p of paths) {
    out.add(resolve(p));
    out.add(realPathFor(p));
  }
  return [...out];
}

function permissionArgs(spec: PermissionSpec, extraReadWrite: string[]): string[] {
  const args = ['--permission'];
  const read = bothForms([...spec.read, ...spec.write, ...extraReadWrite]);
  const write = bothForms([...spec.write, ...extraReadWrite]);
  for (const p of read) args.push(`--allow-fs-read=${p}`);
  for (const p of write) args.push(`--allow-fs-write=${p}`);
  if (spec.allowChildProcess) args.push('--allow-child-process');
  if (spec.allowWorker) args.push('--allow-worker');
  // Node 26 also gates networking under --permission. The app under test must listen on loopback and the
  // flag has no host filter, so network access is granted (and the reports say it is not restricted).
  if (spec.allowNet !== false) args.push('--allow-net');
  return args;
}

/**
 * Starts `node` or `npm` for a generated app. `node` runs under the permission model when `permission` is given
 * and the running Node supports it; otherwise the returned handle/result says `sandboxMode: 'none'` with a warning.
 */
export function spawnSandboxed(opts: SpawnSandboxedOptions): SandboxedProcess {
  const warnings: string[] = [];
  const base = opts.projectDir ?? opts.cwd;
  const localDirs = [join(base, 'home'), join(base, 'tmp')];
  for (const d of localDirs) mkdirSync(d, { recursive: true });

  if (opts.cmd === 'node') {
    let sandboxMode: SandboxMode = 'none';
    let args = [...opts.args];
    let file = process.execPath;
    if (opts.permission) {
      for (const dir of opts.permission.write) mkdirSync(dir, { recursive: true });
      if (detectPermissionSupport()) {
        sandboxMode = 'node-permission-model';
        args = [...permissionArgs(opts.permission, localDirs), ...opts.args];
      } else {
        warnings.push(
          'This version of Node does not support the permission model, so the generated app ran without file-system restrictions.',
        );
      }
      // The network fence: loopback only, unless the caller says the app must reach outside hosts.
      const wantsOutside = opts.permission.network === 'any' || (opts.env?.['OUTBOUND_ALLOWED_HOSTS'] ?? '') !== '';
      if (!wantsOutside) {
        const fence = detectNetworkFence();
        if (fence.kind !== 'none') {
          ({ file, args } = fence.wrap(file, args));
          if (sandboxMode === 'node-permission-model') sandboxMode = 'node-permission-model+loopback-only';
        } else {
          warnings.push('No network fence is available on this computer, so the generated app ran with network access.');
        }
      }
    }
    return spawnCommand(file, args, { ...opts, sandboxMode, warnings, envKind: 'node' });
  }

  const npm = resolveNpm();
  if (npm.kind === 'node-script') {
    return spawnCommand(process.execPath, [npm.script, ...opts.args], { ...opts, sandboxMode: 'none', warnings, envKind: 'npm' });
  }
  warnings.push('npm was not found next to Node; using the npm on PATH.');
  return spawnCommand(npm.file, opts.args, { ...opts, sandboxMode: 'none', warnings, envKind: 'npm' });
}

export type RunOptions = Omit<SpawnSandboxedOptions, 'cmd' | 'args'>;

export function runNode(args: string[], opts: RunOptions): Promise<ProcessResult> {
  return spawnSandboxed({ ...opts, cmd: 'node', args }).wait();
}

export function runNpm(args: string[], opts: RunOptions): Promise<ProcessResult> {
  return spawnSandboxed({ ...opts, cmd: 'npm', args }).wait();
}

/** Runs any executable (external scanners) with the same conventions; never sandboxed by the permission model. */
export function runCommand(file: string, args: string[], opts: RunOptions): Promise<ProcessResult> {
  return spawnCommand(file, args, { ...opts, sandboxMode: 'none' }).wait();
}

/** Removes a throw-away directory created for a child process; errors are ignored. */
export function removeDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // best effort
  }
}
