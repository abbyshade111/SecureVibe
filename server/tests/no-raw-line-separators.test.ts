/**
 * No source file may hold a raw U+2028 (line separator) or U+2029 (paragraph separator).
 *
 * `generator/recipes/js-literal.ts` exists because either character, raw inside emitted JavaScript, is a line
 * terminator to the parser and invisible to a reader: the app breaks and nobody can see why. The same character
 * in the helper's own file broke the helper the day it was written, and review cannot catch a reintroduction
 * because there is nothing to see. So this looks at the bytes. Tests that need the character build it with
 * String.fromCharCode(0x2028) and stay clean by construction.
 */
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from './knowledge/helpers.js';

const ROOTS = ['server/src', 'server/tests', 'shared/src', 'web/src', 'templates/secure-web-app'];
const SKIP_DIRS = new Set(['node_modules', 'dist', 'target', '.git']);
const SOURCE = /\.(ts|tsx|js|mjs|cjs|json|ejs|css|html|md|txt)$/;
// Built from char codes so this file is itself clean by construction.
const RAW_SEPARATOR = new RegExp(`${String.fromCharCode(0x2028)}|${String.fromCharCode(0x2029)}`);

function walk(dir: string, out: string[]): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (SOURCE.test(entry)) out.push(full);
  }
  return out;
}

/** "file:line" for every line holding a raw separator; the character itself is not printed, it cannot be seen. */
export function findRawLineSeparators(files: string[]): string[] {
  const hits: string[] = [];
  for (const file of files) {
    const lines = readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, i) => {
      if (RAW_SEPARATOR.test(line)) hits.push(`${relative(REPO_ROOT, file)}:${i + 1}`);
    });
  }
  return hits;
}

describe('raw line and paragraph separators', () => {
  it('appear in no source file', () => {
    const files = ROOTS.flatMap((root) => walk(join(REPO_ROOT, root), []));
    // The scan must have found the file whose existence is the reason for this test.
    expect(files.some((f) => f.endsWith(join('generator', 'recipes', 'js-literal.ts')))).toBe(true);
    expect(files.length).toBeGreaterThan(200);
    expect(findRawLineSeparators(files)).toEqual([]);
  });

  it('would report one, with its file and line', () => {
    // The check is only known to work when it catches the thing it guards against.
    const dir = join(process.env['SECUREVIBE_HOME']!, 'separator-probe');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, 'probe.ts');
    writeFileSync(file, `const a = 1;\nconst b = 'x${String.fromCharCode(0x2028)}y';\n`);
    expect(findRawLineSeparators([file])).toEqual([`${relative(REPO_ROOT, file)}:2`]);
  });
});
