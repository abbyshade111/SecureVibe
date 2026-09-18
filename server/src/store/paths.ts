/**
 * Path confinement (CONTRACTS §9.6): every path SecureVibe reads or writes on behalf of a request is resolved with
 * realpath and checked against a root folder. The check folds case (macOS and Windows file systems are usually
 * case-insensitive) and rejects NUL bytes and UNC / device paths outright.
 */
import { existsSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, resolve, sep } from 'node:path';

export class PathConfinementError extends Error {
  constructor(
    message: string,
    readonly attempted: string,
  ) {
    super(message);
    this.name = 'PathConfinementError';
  }
}

const UNC_OR_DEVICE = /^(\\\\|\/\/|\\\\\?\\|\\\\\.\\)/;

/** Real path of the deepest existing ancestor joined with the remaining (not yet created) segments. */
export function realpathLenient(path: string): string {
  const absolute = resolve(path);
  const missing: string[] = [];
  let probe = absolute;
  while (!existsSync(probe)) {
    const parent = dirname(probe);
    if (parent === probe) return absolute;
    missing.unshift(probe.slice(parent.length + 1));
    probe = parent;
  }
  let real: string;
  try {
    real = realpathSync.native(probe);
  } catch {
    real = probe;
  }
  return missing.length ? resolve(real, ...missing) : real;
}

function fold(path: string): string {
  return process.platform === 'win32' || process.platform === 'darwin' ? path.toLowerCase() : path;
}

/** True when `target` (real, resolved) is `root` itself or lives underneath it. */
export function isWithin(root: string, target: string): boolean {
  const r = fold(realpathLenient(root)).replace(new RegExp(`\\${sep}+$`), '');
  const t = fold(realpathLenient(target));
  return t === r || t.startsWith(r + sep);
}

function rejectSuspicious(segment: string): void {
  if (segment.includes('\0')) throw new PathConfinementError('The path contains a NUL byte.', segment);
  if (UNC_OR_DEVICE.test(segment)) throw new PathConfinementError('UNC and device paths are not allowed.', segment);
}

/**
 * Resolves `segments` under `root` and returns the absolute path, or throws PathConfinementError when the result would
 * escape the root (through `..`, an absolute segment, a symlink, or a case trick).
 */
export function confinePath(root: string, ...segments: string[]): string {
  rejectSuspicious(root);
  for (const s of segments) {
    rejectSuspicious(s);
    if (isAbsolute(s)) throw new PathConfinementError('Absolute paths are not allowed here.', s);
  }
  const candidate = resolve(root, ...segments);
  if (!isWithin(root, candidate)) {
    throw new PathConfinementError('The path points outside the allowed folder.', candidate);
  }
  return candidate;
}

/** A relative path safe to show and to use in URLs: no `..`, no leading slash, forward slashes. */
export function safeRelative(path: string): string | undefined {
  if (path.includes('\0') || path.includes('\\')) return undefined;
  const parts = path.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.some((p) => p === '..')) return undefined;
  return parts.join('/');
}
