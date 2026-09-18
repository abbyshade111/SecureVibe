/**
 * Preflight checks (CONTRACTS §0 `GET /api/status`, and `securevibe doctor`): node-version, api-key,
 * npm-registry reachability, workspace-writable, port, disk-space. Every check is plain-language and says how to
 * fix itself when it is not ok; only `blocking` ones stop a build.
 */
import { accessSync, constants, promises as fsp, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PreflightCheck } from '@shared/api.js';
import { hasCredentials } from '../integration.js';
import type { SecureVibeConfig } from '../config.js';

const MIN_NODE_MAJOR = 22;
const MIN_NODE_MINOR = 13;
const REGISTRY_TIMEOUT_MS = 3000;
const MIN_FREE_BYTES = 500 * 1024 * 1024; // 500 MB: comfortably more than one build needs

function parseNodeVersion(version: string): { major: number; minor: number } {
  const m = /^v?(\d+)\.(\d+)/.exec(version);
  return { major: m ? Number(m[1]) : 0, minor: m ? Number(m[2]) : 0 };
}

export function checkNodeVersion(version: string = process.version): PreflightCheck {
  const { major, minor } = parseNodeVersion(version);
  const ok = major > MIN_NODE_MAJOR || (major === MIN_NODE_MAJOR && minor >= MIN_NODE_MINOR);
  return {
    id: 'node-version',
    ok,
    title: 'Node.js version',
    detail: ok
      ? `Node.js ${version} meets the minimum (${MIN_NODE_MAJOR}.${MIN_NODE_MINOR}+).`
      : `Node.js ${version} is older than the minimum SecureVibe needs (${MIN_NODE_MAJOR}.${MIN_NODE_MINOR}+). Install a newer version from nodejs.org.`,
    blocking: !ok,
  };
}

export function checkApiKey(): PreflightCheck {
  const configured = hasCredentials();
  return {
    id: 'api-key',
    ok: configured,
    title: 'AI connection',
    detail: configured
      ? 'An Anthropic API key was found. AI features are available.'
      : 'No Anthropic API key was found. SecureVibe will run in Preview mode: a secure baseline app without AI customization or AI review. Add ANTHROPIC_API_KEY to a .env file next to the repository, or set it as an environment variable, then restart.',
    blocking: false,
  };
}

export async function checkNpmRegistry(timeoutMs = REGISTRY_TIMEOUT_MS): Promise<PreflightCheck> {
  const base = {
    id: 'npm-registry' as const,
    title: 'Package registry',
    blocking: false,
  };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch('https://registry.npmjs.org/', { method: 'HEAD', signal: controller.signal });
      return { ...base, ok: res.ok, detail: res.ok ? 'The npm package registry is reachable.' : `The npm package registry answered with status ${res.status}. Installing packages for new apps may fail.` };
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return { ...base, ok: false, detail: 'The npm package registry could not be reached (offline, or a firewall is blocking it). Installing packages for new apps may fail or run from a local cache.' };
  }
}

export function checkWorkspaceWritable(home: string): PreflightCheck {
  const probe = join(home, `.write-test-${process.pid}`);
  try {
    accessSync(home, constants.F_OK);
  } catch {
    // resolvePaths already created it; a missing folder here means it could not be created.
  }
  try {
    writeFileSync(probe, 'ok');
    unlinkSync(probe);
    return { id: 'workspace-writable', ok: true, title: 'Workspace folder', detail: `${home} is writable.`, blocking: true };
  } catch (err) {
    return {
      id: 'workspace-writable',
      ok: false,
      title: 'Workspace folder',
      detail: `${home} is not writable (${err instanceof Error ? err.message : String(err)}). Choose a different folder with SECUREVIBE_HOME, or fix its permissions.`,
      blocking: true,
    };
  }
}

export async function checkPort(port: number, opts: { alreadyBound?: boolean } = {}): Promise<PreflightCheck> {
  if (opts.alreadyBound) {
    return { id: 'port', ok: true, title: 'Port', detail: `SecureVibe is listening on 127.0.0.1:${port}.`, blocking: false };
  }
  const net = await import('node:net');
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => {
      resolve({ id: 'port', ok: false, title: 'Port', detail: `Port ${port} is already in use. Set SECUREVIBE_PORT to a free port, or stop the program using it.`, blocking: true });
    });
    tester.once('listening', () => {
      tester.close(() => resolve({ id: 'port', ok: true, title: 'Port', detail: `Port ${port} is free.`, blocking: true }));
    });
    tester.listen(port, '127.0.0.1');
  });
}

export async function checkDiskSpace(home: string): Promise<PreflightCheck> {
  try {
    const stats = await fsp.statfs(home);
    const freeBytes = stats.bavail * stats.bsize;
    const ok = freeBytes >= MIN_FREE_BYTES;
    const freeMb = Math.round(freeBytes / (1024 * 1024));
    return {
      id: 'disk-space',
      ok,
      title: 'Disk space',
      detail: ok ? `${freeMb} MB free.` : `Only ${freeMb} MB free where SecureVibe stores projects. Free up space before building an app.`,
      blocking: false,
    };
  } catch {
    return { id: 'disk-space', ok: true, title: 'Disk space', detail: 'Could not measure free disk space on this system; assuming it is fine.', blocking: false };
  }
}

export async function runPreflight(config: SecureVibeConfig, opts: { alreadyBound?: boolean } = {}): Promise<PreflightCheck[]> {
  const [registry, port, disk] = await Promise.all([checkNpmRegistry(), checkPort(config.port, opts), checkDiskSpace(config.paths.home)]);
  return [checkNodeVersion(), checkApiKey(), registry, checkWorkspaceWritable(config.paths.home), port, disk];
}
