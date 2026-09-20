/**
 * The sentence an owner reads before uploading, and the one the report gives them afterwards, come from the
 * same table on purpose (ADR-012). These check the promise is one the report can keep.
 */
import { describe, expect, it } from 'vitest';
import { languageBreakdown, whatWeCanSay } from '@shared/languages.js';
import { summariseCodeCoverage } from '../../src/compliance/code-coverage.js';

const FLASK_APP = ['run.py', 'manage.py', 'app/__init__.py', 'app/main.py', 'app/auth.py', 'app/db.py', 'app/weather.py', 'static/app.js'];
const NODE_APP = ['src/server.ts', 'src/db.ts', 'src/views/list.ejs', 'public/app.js'];

describe('what we tell somebody before they upload', () => {
  it('promises no score for an app it cannot read, which is what the report then says', () => {
    const said = whatWeCanSay(FLASK_APP);
    expect(said.headline).toContain('Python');
    expect(said.detail).toContain('no compliance score');
    expect(said.detail).toContain('not assessed');
    // And the report agrees: the page must not promise something the run then withholds.
    expect(summariseCodeCoverage(FLASK_APP).assessable).toBe(false);
  });

  it('promises a full check for an app it does read, and the report agrees', () => {
    const said = whatWeCanSay(NODE_APP);
    expect(said.detail).toContain('compliance score');
    expect(said.detail).not.toContain('not assessed');
    expect(summariseCodeCoverage(NODE_APP).assessable).toBe(true);
  });

  it('always promises the checks that do not care what the language is', () => {
    for (const files of [FLASK_APP, NODE_APP, ['main.erl']]) {
      const said = whatWeCanSay(files);
      expect(said.detail).toMatch(/virus scanner/);
      expect(said.detail).toMatch(/passwords and keys/);
    }
  });

  it('says plainly when it can see no code at all, rather than promising a check of nothing', () => {
    const said = whatWeCanSay(['README.md', 'logo.png']);
    expect(said.headline).toContain('No code was found');
    expect(said.detail).toContain('picked the folder');
  });

  it('is one table, so the page and the report cannot drift apart', () => {
    // The failure this guards is subtle: two tables that agree today and diverge when somebody adds a language
    // to one of them. A page that promises what the report withholds is worse than either being wrong alone.
    const fromShared = languageBreakdown(FLASK_APP).map((l) => `${l.language}:${l.files}:${l.analysed}`);
    const fromReport = summariseCodeCoverage(FLASK_APP).languages.map((l) => `${l.language}:${l.files}:${l.read}`);
    expect(fromReport).toEqual(fromShared);
  });
});
