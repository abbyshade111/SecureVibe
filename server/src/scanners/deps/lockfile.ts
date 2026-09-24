/**
 * Reading `package-lock.json`: the package inventory the dependency checks, the license inventory and the
 * fallback SBOM all work from. Only the lockfile is parsed here — nothing is fetched.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface LockedPackage {
  /** Lockfile key, e.g. `node_modules/express` or `node_modules/a/node_modules/b`. */
  key: string;
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  license?: string;
  dev: boolean;
  optional: boolean;
  /** npm runs a postinstall/preinstall script for this package. */
  hasInstallScript: boolean;
  /** `direct` when the root package.json lists it, `dev` for dev-only, otherwise `transitive`. */
  path: 'direct' | 'transitive' | 'dev';
  /** Package names from the root down to this package, when it can be derived from the key. */
  chain: string[];
  deprecated?: string;
}

export interface Lockfile {
  file: string;
  hash: string;
  lockfileVersion: number;
  rootName: string;
  rootVersion: string;
  directDependencies: string[];
  devDependencies: string[];
  packages: LockedPackage[];
}

export function nameFromLockKey(key: string): string {
  const parts = key.split('node_modules/');
  return parts[parts.length - 1] ?? key;
}

/** `node_modules/a/node_modules/@scope/b` → ['a', '@scope/b'] */
export function chainFromLockKey(key: string): string[] {
  return key
    .split('node_modules/')
    .slice(1)
    .map((s) => s.replace(/\/$/, ''))
    .filter(Boolean);
}

interface RawLockEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  license?: string | string[];
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  hasInstallScript?: boolean;
  deprecated?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export function parseLockfile(appDir: string): Lockfile | undefined {
  const file = join(appDir, 'package-lock.json');
  if (!existsSync(file)) return undefined;
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
  let raw: { lockfileVersion?: number; name?: string; version?: string; packages?: Record<string, RawLockEntry> };
  try {
    raw = JSON.parse(text) as typeof raw;
  } catch {
    return undefined;
  }
  const entries = raw.packages ?? {};
  const root = entries[''] ?? {};
  const direct = new Set(Object.keys(root.dependencies ?? {}));
  const dev = new Set(Object.keys(root.devDependencies ?? {}));

  const packages: LockedPackage[] = [];
  for (const [key, entry] of Object.entries(entries)) {
    if (key === '' || !key.includes('node_modules/')) continue;
    const name = entry.name ?? nameFromLockKey(key);
    const isDev = Boolean(entry.dev ?? entry.devOptional);
    const chain = chainFromLockKey(key);
    const path: LockedPackage['path'] = isDev || dev.has(name) ? 'dev' : direct.has(name) ? 'direct' : 'transitive';
    packages.push({
      key,
      name,
      version: entry.version ?? '0.0.0',
      resolved: entry.resolved,
      integrity: entry.integrity,
      license: Array.isArray(entry.license) ? entry.license.join(' OR ') : entry.license,
      dev: isDev,
      optional: Boolean(entry.optional),
      hasInstallScript: entry.hasInstallScript === true,
      path,
      chain,
      deprecated: entry.deprecated,
    });
  }

  return {
    file,
    hash: createHash('sha256').update(text).digest('hex'),
    lockfileVersion: raw.lockfileVersion ?? 0,
    rootName: root.name ?? raw.name ?? 'app',
    rootVersion: root.version ?? raw.version ?? '0.0.0',
    directDependencies: [...direct],
    devDependencies: [...dev],
    packages,
  };
}

/** Package URL for an npm package; the scope's `@` must be percent-encoded. */
export function purlFor(name: string, version: string): string {
  const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}
