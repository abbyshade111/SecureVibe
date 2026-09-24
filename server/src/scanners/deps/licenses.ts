/**
 * License inventory: reads the `license` field of every installed package under `node_modules` (falling back to
 * the lockfile when the packages are not installed) so the report can list what the app depends on and flag the
 * licenses that come with sharing obligations.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { LockedPackage } from './lockfile.js';

export interface LicenseEntry {
  name: string;
  version: string;
  license: string;
  path: 'direct' | 'transitive' | 'dev';
  /** Where the value came from, so the report can be honest about unknowns. */
  source: 'node_modules' | 'lockfile' | 'unknown';
}

/**
 * Licenses that require you to share your own source code (or your changes) when you distribute the app.
 * For a locally-run app this is information, not a security problem — hence severity `info` in CONTRACTS §4.
 */
const COPYLEFT = [/^AGPL/i, /^GPL/i, /^LGPL/i, /^MPL-2/i, /^EPL/i, /^CDDL/i, /^OSL/i, /^SSPL/i, /^EUPL/i, /^CPAL/i];

export function isCopyleft(license: string): boolean {
  return COPYLEFT.some((re) => re.test(license.trim().replace(/^\(|\)$/g, '')));
}

function readPackageLicense(dir: string): { name?: string; version?: string; license?: string } | undefined {
  const file = join(dir, 'package.json');
  if (!existsSync(file)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8')) as {
      name?: string;
      version?: string;
      license?: string | { type?: string };
      licenses?: { type?: string }[];
    };
    const license =
      typeof raw.license === 'string'
        ? raw.license
        : (raw.license?.type ?? raw.licenses?.map((l) => l.type).filter(Boolean).join(' OR '));
    return { name: raw.name, version: raw.version, license: license || undefined };
  } catch {
    return undefined;
  }
}

/** Walks `node_modules`, including scoped folders and nested `node_modules`, up to `maxDepth` nesting levels. */
export function walkNodeModules(root: string, maxDepth = 4): { dir: string; name: string }[] {
  const out: { dir: string; name: string }[] = [];
  const visit = (modulesDir: string, depth: number): void => {
    if (depth > maxDepth || !existsSync(modulesDir)) return;
    let entries: string[];
    try {
      entries = readdirSync(modulesDir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.startsWith('.')) continue;
      const full = join(modulesDir, entry);
      try {
        if (!statSync(full).isDirectory()) continue;
      } catch {
        continue;
      }
      if (entry.startsWith('@')) {
        let scoped: string[];
        try {
          scoped = readdirSync(full);
        } catch {
          continue;
        }
        for (const inner of scoped) {
          const innerDir = join(full, inner);
          out.push({ dir: innerDir, name: `${entry}/${inner}` });
          visit(join(innerDir, 'node_modules'), depth + 1);
        }
        continue;
      }
      out.push({ dir: full, name: entry });
      visit(join(full, 'node_modules'), depth + 1);
    }
  };
  visit(root, 0);
  return out;
}

export function collectLicenses(appDir: string, locked: LockedPackage[]): LicenseEntry[] {
  const byName = new Map<string, LockedPackage>();
  for (const pkg of locked) if (!byName.has(pkg.name)) byName.set(pkg.name, pkg);

  const entries = new Map<string, LicenseEntry>();
  for (const found of walkNodeModules(join(appDir, 'node_modules'))) {
    const meta = readPackageLicense(found.dir);
    if (!meta) continue;
    const name = meta.name ?? found.name;
    const version = meta.version ?? byName.get(name)?.version ?? '0.0.0';
    const key = `${name}@${version}`;
    if (entries.has(key)) continue;
    entries.set(key, {
      name,
      version,
      license: meta.license ?? 'UNKNOWN',
      path: byName.get(name)?.path ?? 'transitive',
      source: meta.license ? 'node_modules' : 'unknown',
    });
  }

  // Packages that are locked but not installed still belong in the inventory.
  for (const pkg of locked) {
    const key = `${pkg.name}@${pkg.version}`;
    if (entries.has(key)) continue;
    entries.set(key, {
      name: pkg.name,
      version: pkg.version,
      license: pkg.license ?? 'UNKNOWN',
      path: pkg.path,
      source: pkg.license ? 'lockfile' : 'unknown',
    });
  }

  return [...entries.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

export function summarizeLicenses(entries: LicenseEntry[]): { license: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const e of entries) counts.set(e.license, (counts.get(e.license) ?? 0) + 1);
  return [...counts.entries()]
    .map(([license, count]) => ({ license, count }))
    .sort((a, b) => b.count - a.count || a.license.localeCompare(b.license));
}
