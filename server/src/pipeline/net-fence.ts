/**
 * The network fence for generated code (docs/CONTRACTS.md "Network fence").
 *
 * Node's permission model restricts the file system but its network permission is all-or-nothing, and the app under
 * test must listen on loopback. So the fence comes from the operating system instead: on macOS the process runs
 * under `sandbox-exec` with a profile that allows loopback and nothing else; on Linux it runs in its own network
 * namespace with only `lo` up. Either way the app can serve and be probed on 127.0.0.1 and cannot reach anything
 * else — no data leaves the computer while SecureVibe runs generated code. Where neither tool works the fence is
 * absent and every report says so.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';

export type FenceKind = 'macos-seatbelt' | 'linux-netns' | 'none';

/** Seatbelt profile: everything the permission model already allows, minus every network path but loopback. */
export const SEATBELT_LOOPBACK_PROFILE = [
  '(version 1)',
  '(allow default)',
  '(deny network*)',
  '(allow network-bind (local ip "localhost:*"))',
  '(allow network-inbound (local ip "localhost:*"))',
  '(allow network-outbound (remote ip "localhost:*"))',
  '(allow network* (local unix-socket))',
  '(allow network* (remote unix-socket))',
].join('\n');

const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
/** Inside the namespace `lo` is down; bring it up, then run the real command. */
const NETNS_SHIM = 'ip link set lo up 2>/dev/null; exec "$0" "$@"';

export interface Fence {
  kind: FenceKind;
  /** Wraps a command so it runs behind the fence; the identity function when `kind` is 'none'. */
  wrap(file: string, args: string[]): { file: string; args: string[] };
}

const noFence: Fence = { kind: 'none', wrap: (file, args) => ({ file, args }) };

let detected: Fence | undefined;

function probe(file: string, args: string[]): boolean {
  try {
    const r = spawnSync(file, args, { timeout: 15_000, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin:/usr/sbin:/sbin' } });
    return r.status === 0;
  } catch {
    return false;
  }
}

/** The fence this computer can provide, probed once per process (a tiny node run behind the fence must succeed). */
export function detectNetworkFence(): Fence {
  if (detected) return detected;
  if (process.platform === 'darwin' && existsSync(SANDBOX_EXEC) && probe(SANDBOX_EXEC, ['-p', SEATBELT_LOOPBACK_PROFILE, process.execPath, '-e', 'process.exit(0)'])) {
    detected = { kind: 'macos-seatbelt', wrap: (file, args) => ({ file: SANDBOX_EXEC, args: ['-p', SEATBELT_LOOPBACK_PROFILE, file, ...args] }) };
  } else if (process.platform === 'linux' && probe('unshare', ['-rn', 'sh', '-c', 'ip link set lo up && exit 0'])) {
    detected = { kind: 'linux-netns', wrap: (file, args) => ({ file: 'unshare', args: ['-rn', 'sh', '-c', NETNS_SHIM, file, ...args] }) };
  } else {
    detected = noFence;
  }
  return detected;
}

/** Tests only: forget (or force) the detection result. */
export function resetNetworkFenceDetection(value?: Fence): void {
  detected = value;
}
