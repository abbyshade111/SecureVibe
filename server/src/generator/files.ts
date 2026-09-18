/**
 * Small, self-contained file-tree helpers for the generator (kept local rather than reaching into another
 * module's internals): listing a generated app's files, hashing them, and matching the manifest's glob path
 * lists (which use a leading `!` to re-open an otherwise-protected file, e.g. `src/features/ai/prompt.ts`).
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

export interface AppFile {
  /** Posix path relative to the app root. */
  relPath: string;
  absPath: string;
}

export const DEFAULT_WALK_IGNORE = ['node_modules', '.git', 'data', 'dist', 'coverage', 'home', 'tmp', 'certs', '.DS_Store'];

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

/** Lists every regular file under `root` (sorted, posix-relative), skipping the given top-level-or-anywhere names. */
export function listFiles(root: string, ignore: string[] = DEFAULT_WALK_IGNORE): AppFile[] {
  const out: AppFile[] = [];
  const ignoreSet = new Set(ignore);
  const walk = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort()) {
      if (ignoreSet.has(name)) continue;
      const abs = join(dir, name);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(abs);
      else if (st.isFile()) out.push({ relPath: toPosix(relative(root, abs)), absPath: abs });
    }
  };
  walk(root);
  return out;
}

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

/** Converts one glob (`*` within a segment, `**` any depth) into an anchored regular expression. */
export function globToRegex(glob: string): RegExp {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        const slashAfter = glob[i + 2] === '/';
        i += slashAfter ? 2 : 1;
        out += slashAfter ? '(?:.*/)?' : '.*';
      } else {
        out += '[^/]*';
      }
    } else if ('\\^$.|+()[]{}?'.includes(ch)) out += `\\${ch}`;
    else out += ch;
  }
  return new RegExp(`^${out}$`);
}

/** True when `relPath` matches any glob in `globs`; a `!glob` entry removes an earlier match (order matters). */
export function matchesAnyGlob(relPath: string, globs: string[]): boolean {
  let matched = false;
  for (const g of globs) {
    if (g.startsWith('!')) {
      if (globToRegex(g.slice(1)).test(relPath)) matched = false;
    } else if (globToRegex(g).test(relPath)) {
      matched = true;
    }
  }
  return matched;
}

/**
 * Hash of the security-critical (protected) files of an app, as a person reviews them: a recorded human code
 * review counts only while this hash is unchanged.
 */
export function protectedTreeHash(appDir: string, protectedPaths: string[]): { hash: string; files: string[] } {
  const files = listFiles(appDir)
    .filter((f) => matchesAnyGlob(f.relPath, protectedPaths))
    .sort((a, b) => a.relPath.localeCompare(b.relPath));
  const hash = createHash('sha256');
  for (const f of files) hash.update(`${f.relPath}:${sha256File(f.absPath) ?? ''}\n`);
  return { hash: hash.digest('hex'), files: files.map((f) => f.relPath) };
}
