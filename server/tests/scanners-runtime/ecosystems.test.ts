/**
 * Not asking an app questions about a package manager it does not use (ADR-012).
 *
 * The Flask app that prompted this was told `deps.lockfile-missing` and marked down for not setting
 * `ignore-scripts=true` in an `.npmrc` it has no reason to own. Those are not coverage gaps — a gap is honest
 * and visible — they are a report saying something untrue out loud.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { detectEcosystems, unpinnedEcosystems, usesNpm } from '../../src/scanners/ecosystems.js';
import { semgrepPacks } from '../../src/scanners/external/index.js';

const dirs: string[] = [];
function appWith(files: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'sv-eco-'));
  dirs.push(dir);
  for (const f of files) writeFileSync(join(dir, f), '');
  return dir;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('which package managers an app actually uses', () => {
  it('knows a Python app is not an npm app missing a lockfile', () => {
    const dir = appWith(['requirements.txt']);
    expect(usesNpm(dir)).toBe(false);
    expect(detectEcosystems(dir)).toEqual([{ name: 'Python', manifest: 'requirements.txt' }]);
  });

  it('knows an app can be both, and does not make it choose', () => {
    // A Python service with a JavaScript front end: both sets of checks should run, not one or the other.
    const dir = appWith(['requirements.txt', 'package.json', 'package-lock.json']);
    expect(usesNpm(dir)).toBe(true);
    expect(detectEcosystems(dir).map((e) => e.name).sort()).toEqual(['Python', 'npm']);
  });

  it('reports an ecosystem that pins nothing, which is the question underneath the npm one', () => {
    const unpinned = unpinnedEcosystems(appWith(['requirements.txt']));
    expect(unpinned.map((e) => e.manifest)).toEqual(['requirements.txt']);
    // With versions written down, there is nothing to report.
    expect(unpinnedEcosystems(appWith(['requirements.txt', 'poetry.lock']))).toEqual([]);
  });
});

describe('which semgrep rules are worth asking for', () => {
  it('asks for the language that is there, not the language we happen to write', () => {
    expect(semgrepPacks(['app/main.py', 'app/auth.py', 'static/app.js'])).toEqual(['p/owasp-top-ten', 'p/javascript', 'p/python']);
    expect(semgrepPacks(['src/server.ts', 'src/views/list.ejs'])).toEqual(['p/owasp-top-ten', 'p/typescript']);
  });

  it('still asks for the cross-language rules when it recognizes no language at all', () => {
    // An app written in something we do not list is not left with nothing.
    expect(semgrepPacks(['main.erl', 'README.md'])).toEqual(['p/owasp-top-ten']);
  });
});
