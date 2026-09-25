/**
 * No node_modules path may be tracked, real or symlinked.
 *
 * A worktree gets its dependencies through a symlink named node_modules, and the ignore rule "node_modules/" only
 * matches directories, so `git add -A` committed the link. Twice: an absolute path into one person's checkout,
 * which on anyone else's machine replaces an ignored real node_modules folder on checkout. Nothing caught it
 * because the check-in review filtered "node_modules" out of the status listing to keep the noise down.
 */
import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from './knowledge/helpers.js';

function trackedFiles(): string[] | undefined {
  try {
    return execFileSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).split('\0').filter(Boolean);
  } catch {
    return undefined; // not a git checkout (an exported tree): nothing to check
  }
}

describe('tracked files', () => {
  it('include no node_modules path, whether a folder or a symbolic link', (ctx) => {
    const files = trackedFiles();
    if (!files) return ctx.skip();
    expect(files.length).toBeGreaterThan(100);
    const bad = files.filter((f) => f.split('/').includes('node_modules'));
    expect(bad, `tracked, but must not be: ${bad.join(', ')}`).toEqual([]);
  });
});
