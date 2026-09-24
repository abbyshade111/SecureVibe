/**
 * File-tree helpers shared by the static scanners: listing the app's files with gitignore-style ignore
 * patterns, reading text safely, hashing, and looking up where a file came from (provenance).
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { Finding } from '@shared/findings.js';
import type { ScanContext } from '../types.js';

export interface AppFile {
  /** Posix path relative to the app root, e.g. "src/features/notes/routes.ts". */
  relPath: string;
  absPath: string;
  size: number;
}

/** Folders and files no scanner ever looks into. */
export const DEFAULT_IGNORE = ['node_modules', 'data', 'dist', '.git', 'coverage', 'certs', '.DS_Store'];

const MAX_TEXT_BYTES = 1_000_000;

export function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

function escapeRegex(s: string): string {
  return s.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/**
 * Converts one gitignore-style pattern to a regular expression over posix relative paths.
 * A bare name (no slash, no glob) matches that name anywhere in the tree, like gitignore does.
 */
export function ignorePatternToRegex(pattern: string): RegExp {
  let p = pattern.trim();
  if (p.startsWith('/')) p = p.slice(1);
  if (p.endsWith('/')) p = p.slice(0, -1);
  const body = escapeRegex(p)
    .replace(/\*\*\//g, '(?:.*/)?')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]');
  // A pattern without a slash matches at any depth (like .gitignore); one with a slash is anchored to the root.
  if (!p.includes('/')) return new RegExp(`(^|/)${body}(/|$)`);
  return new RegExp(`^${body}(/|$)`);
}

export function isIgnored(relPath: string, patterns: RegExp[]): boolean {
  return patterns.some((re) => re.test(relPath));
}

export function compileIgnore(extra: string[] = []): RegExp[] {
  return [...DEFAULT_IGNORE, ...extra].map(ignorePatternToRegex);
}

/** Lists every regular file under appDir (sorted, posix relative paths), honouring the ignore patterns. */
export function listAppFiles(appDir: string, extraIgnore: string[] = []): AppFile[] {
  const patterns = compileIgnore(extraIgnore);
  const out: AppFile[] = [];
  const walk = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort()) {
      const abs = join(dir, name);
      const rel = toPosix(relative(appDir, abs));
      if (isIgnored(rel, patterns)) continue;
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(abs);
      else if (st.isFile()) out.push({ relPath: rel, absPath: abs, size: st.size });
    }
  };
  walk(appDir);
  return out;
}

/** Reads a file as UTF-8 text; returns undefined for binary-looking or oversized files. */
export function readTextFile(absPath: string): string | undefined {
  let buf: Buffer;
  try {
    buf = readFileSync(absPath);
  } catch {
    return undefined;
  }
  if (buf.length > MAX_TEXT_BYTES) return undefined;
  const probe = buf.subarray(0, 8192);
  if (probe.includes(0)) return undefined;
  return buf.toString('utf8');
}

/** Content hashes for files and fingerprints, never for passwords (those use argon2/scrypt in the template). */
export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256File(absPath: string): string | undefined {
  try {
    return sha256(readFileSync(absPath));
  } catch {
    return undefined;
  }
}

export type IntroducedBy = Finding['introducedBy'];

/**
 * Who wrote a file, from the provenance record. A file whose content no longer matches the recorded
 * hash was changed after generation, which we attribute to the user.
 */
export function originFor(ctx: Pick<ScanContext, 'provenance'>, relPath: string, content?: string | Buffer): IntroducedBy {
  const entry = ctx.provenance?.generatedFiles.find((f) => f.path === relPath);
  if (!entry) return 'unknown';
  if (content !== undefined && sha256(content) !== entry.sha256) return 'user';
  switch (entry.origin) {
    case 'template':
    case 'expanded':
      return 'template';
    case 'ai-generated':
      return 'ai-generated';
    case 'ai-fixed':
      return 'ai-fixed';
    case 'user':
      return 'user';
    default:
      return 'unknown';
  }
}

/** True when a relative path matches one of the manifest's glob paths (e.g. "src/security/**"). */
export function matchesAnyGlob(relPath: string, globs: string[]): boolean {
  return globs.some((g) => globToRegex(g).test(relPath));
}

export function globToRegex(glob: string): RegExp {
  const body = escapeRegex(glob.trim())
    .replace(/\*\*\//g, '(?:.*/)?')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]');
  return new RegExp(`^${body}$`);
}
