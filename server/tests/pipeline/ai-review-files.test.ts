/** What the AI review is handed: every language it can read, security code first, and nothing from node_modules. */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { collectFiles, reviewPriority } from '../../src/pipeline/stages/ai-review.js';

function app(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'sv-review-files-'));
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return dir;
}

describe('the files the AI review reads', () => {
  it('hands over a Python app, with its security code first', () => {
    // The Flask app of 20 September 2026: seven .py files, and the review saw none of them.
    const dir = app({
      'main.py': 'app = Flask(__name__)',
      'auth.py': 'def login(): pass',
      'db.py': 'import sqlite3',
      'requirements.txt': 'flask',
      'static/app.js': 'console.log(1)',
      'templates/index.html': '<html></html>',
      'tests/test_auth.py': 'def test_x(): pass',
      'README.md': '# hi',
      'node_modules/x/index.js': 'x',
      'logo.png': 'binary',
    });
    const paths = collectFiles(dir, []).map((f) => f.path);
    expect(paths[0]).toBe('auth.py');
    expect(paths).toContain('main.py');
    expect(paths).toContain('db.py');
    expect(paths).toContain('static/app.js');
    expect(paths).toContain('templates/index.html');
    expect(paths).toContain('requirements.txt');
    expect(paths.at(-1)).toBe('tests/test_auth.py');
    expect(paths).not.toContain('README.md');
    expect(paths).not.toContain('logo.png');
    expect(paths.some((p) => p.startsWith('node_modules/'))).toBe(false);
  });

  it('still reads a SecureVibe app the way it did: TypeScript, views, package.json', () => {
    const dir = app({ 'src/app.ts': '', 'src/security/headers.ts': '', 'views/home.ejs': '', 'package.json': '{}', 'src/x.test.ts': '' });
    expect(collectFiles(dir, []).map((f) => f.path)).toEqual(['src/app.ts', 'src/security/headers.ts', 'views/home.ejs', 'package.json', 'src/x.test.ts']);
  });

  it('orders security code first in any language, and tests last', () => {
    expect(reviewPriority('auth.py')).toBe(0);
    expect(reviewPriority('app/sessions.rb')).toBe(0);
    expect(reviewPriority('src/lib/util.go')).toBe(1);
    expect(reviewPriority('templates/x.html')).toBe(2);
    expect(reviewPriority('go.mod')).toBe(3);
    expect(reviewPriority('tests/test_login.py')).toBe(4);
    expect(reviewPriority('src/auth.spec.js')).toBe(4);
  });
});
