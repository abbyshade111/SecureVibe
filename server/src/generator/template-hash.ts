/**
 * "Is there a newer template than the one this app was built from?"
 *
 * The template has a version number, but it changes far more often than that number does, so the comparison is
 * made on a hash of the template's files. Every scaffold writes the hash into the app's provenance; the API
 * compares it with the template as it is now.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEFAULT_WALK_IGNORE, listFiles, sha256File } from './files.js';

/** Files that are per-app or per-machine and say nothing about the template itself. */
export const TEMPLATE_HASH_IGNORE = [
  ...DEFAULT_WALK_IGNORE,
  '.env',
  '.claude',
  'securevibe.features.json',
  'securevibe.design.json',
  'securevibe.provenance.json',
  'routes.manifest.json',
  'crypto-inventory.json',
  'FIRST-LOGIN.txt',
];

const cache = new Map<string, { at: number; hash: string }>();
const CACHE_MS = 15_000;

/** Hash of the template's files (paths and contents). Cached briefly: the API asks for every project in a list. */
export function templateHash(templateDir: string): string {
  const hit = cache.get(templateDir);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.hash;
  const h = createHash('sha256');
  for (const f of listFiles(templateDir, TEMPLATE_HASH_IGNORE)) h.update(`${f.relPath}\0${sha256File(f.absPath) ?? ''}\n`);
  const hash = h.digest('hex');
  cache.set(templateDir, { at: Date.now(), hash });
  return hash;
}

/** The template hash recorded in an app's provenance; undefined when the app has no provenance file. */
export function appTemplateHash(appDir: string): { hash?: string; hasProvenance: boolean } {
  const file = join(appDir, 'securevibe.provenance.json');
  if (!existsSync(file)) return { hasProvenance: false };
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { templateHash?: unknown };
    return { hasProvenance: true, ...(typeof parsed.templateHash === 'string' ? { hash: parsed.templateHash } : {}) };
  } catch {
    return { hasProvenance: false };
  }
}

/**
 * True when the app was built from a template that differs from the current one. An app built before the hash
 * was recorded counts as outdated (the template has changed since then). Undefined when there is no built app.
 */
export function templateOutdated(appDir: string, templateDir: string): boolean | undefined {
  const app = appTemplateHash(appDir);
  if (!app.hasProvenance) return undefined;
  if (!app.hash) return true;
  return app.hash !== templateHash(templateDir);
}
