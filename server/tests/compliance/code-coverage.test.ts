/**
 * The fact that stops a report scoring code it never read. See code-coverage.ts for the run that caused it.
 */
import { describe, expect, it } from 'vitest';
import { summariseCodeCoverage } from '../../src/compliance/code-coverage.js';

/** The app that started this: 7 Python files, 1 JavaScript, 1 HTML, plus non-code. */
const FITNESS_TRACKER = [
  'run.py',
  'manage.py',
  'app/__init__.py',
  'app/main.py',
  'app/auth.py',
  'app/db.py',
  'app/weather.py',
  'static/app.js',
  'static/index.html',
  'static/styles.css',
  'requirements.txt',
  'README.md',
];

describe('what SecureVibe could read', () => {
  it('refuses to call an app assessable when it read almost none of it', () => {
    const c = summariseCodeCoverage(FITNESS_TRACKER);
    expect(c.codeFiles).toBe(8); // 7 python + 1 javascript; html, css, txt and md are not code files
    expect(c.filesRead).toBe(1);
    expect(c.assessable).toBe(false);
    expect(c.unreadLanguages).toEqual(['Python']);
    expect(c.summary).toContain("read 1 of this app's 8 code files");
    expect(c.summary).toContain('cannot read Python');
  });

  it('an app it can read is assessable, and says so without a caveat', () => {
    const c = summariseCodeCoverage(['src/server.ts', 'src/db.ts', 'src/views/list.ejs', 'public/app.js', 'README.md']);
    expect(c.codeFiles).toBe(4);
    expect(c.filesRead).toBe(4);
    expect(c.assessable).toBe(true);
    expect(c.unreadLanguages).toEqual([]);
    expect(c.summary).toBe("SecureVibe read 4 of this app's 4 code files.");
  });

  it('a few unreadable files do not withhold a score, because that is not the failure being caught', () => {
    const mostly = [...Array(9)].map((_, i) => `src/file${i}.ts`).concat(['scripts/deploy.sh']);
    const c = summariseCodeCoverage(mostly);
    expect(c.assessable).toBe(true);
    expect(c.unreadLanguages).toEqual(['Shell scripts']);
    // Still said out loud: assessable is not the same as complete.
    expect(c.summary).toContain('cannot read Shell scripts');
  });

  it('an app with no code at all is not scored either, because "0 of 0" is the same lie', () => {
    const c = summariseCodeCoverage(['README.md', 'requirements.txt', 'static/styles.css']);
    expect(c.codeFiles).toBe(0);
    expect(c.assessable).toBe(false);
    expect(c.summary).toBe('No code files were found in this app, so nothing was read.');
  });

  it('names the languages a person would name, ordered by how much of the app they are', () => {
    const c = summariseCodeCoverage(['a.py', 'b.py', 'c.py', 'd.rb', 'e.ts']);
    expect(c.languages.map((l) => `${l.language}:${l.files}`)).toEqual(['Python:3', 'Ruby:1', 'TypeScript:1']);
    expect(c.unreadLanguages).toEqual(['Python', 'Ruby']);
  });
});
