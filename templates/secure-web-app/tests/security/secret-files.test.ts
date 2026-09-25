/**
 * Secrets at rest are readable by their owner only (contract §1.3, TPL-SECRETS-01, ASVS V13.3.2 least privilege):
 * the generated `.env`, the data folder, the database and the log.
 */
import { after, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { startApp } from '../helpers/app.ts';
import { templateRoot } from '../helpers/features.ts';

const mode = (path: string): number => statSync(path).mode & 0o777;
const tmp: string[] = [];
const scratch = (prefix: string): string => {
  // The real path: on macOS the temp folder is reached through a symlink, and gen-secrets only runs when the path it
  // was started with equals its own resolved location (it did nothing, and exited 0, the first time this ran).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  tmp.push(dir);
  return dir;
};

describe('secret files', () => {
  after(() => {
    for (const dir of tmp) rmSync(dir, { recursive: true, force: true });
  });

  /** Runs a copy of scripts/gen-secrets.ts in a scratch app folder, so the real template's .env is never touched. */
  function genSecretsIn(appDir: string): { status: number | null; stderr: string } {
    mkdirSync(join(appDir, 'scripts'), { recursive: true });
    copyFileSync(join(templateRoot, 'scripts', 'gen-secrets.ts'), join(appDir, 'scripts', 'gen-secrets.ts'));
    copyFileSync(join(templateRoot, '.env.example'), join(appDir, '.env.example'));
    const r = spawnSync(process.execPath, ['--experimental-strip-types', join(appDir, 'scripts', 'gen-secrets.ts')], { cwd: appDir, encoding: 'utf8', env: { PATH: process.env.PATH ?? '' } });
    return { status: r.status, stderr: r.stderr };
  }

  test('V13.3.2 the generated .env, which holds every secret, is readable by its owner only', () => {
    const appDir = scratch('securevibe-gensecrets-');
    const first = genSecretsIn(appDir);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(mode(join(appDir, '.env')), 0o600, 'a new .env must be created owner-only (0600)');
    assert.match(readFileSync(join(appDir, '.env'), 'utf8'), /^SESSION_SECRET=.{32,}$/m, 'the secrets must really be in the file this permission protects');

    // A file that was loosened afterwards is tightened again the next time the script runs, not left as it was.
    chmodSync(join(appDir, '.env'), 0o644);
    const again = genSecretsIn(appDir);
    assert.equal(again.status, 0, again.stderr);
    assert.equal(mode(join(appDir, '.env')), 0o600, 'running the script again must restore owner-only access');
  });

  test('V13.3.2 access to secret assets follows least privilege: the data folder, the database and the log are owner-only, even when the folder was created open to everyone', async () => {
    const dataDir = scratch('securevibe-datadir-');
    chmodSync(dataDir, 0o755);
    writeFileSync(join(dataDir, 'keep'), '');
    assert.equal(mode(dataDir), 0o755, 'the setup must start with an open folder, or the test proves nothing');
    const app = await startApp({ dataDir });
    try {
      assert.equal(mode(dataDir) & 0o077, 0, `the data folder must not be accessible to group or others (is ${mode(dataDir).toString(8)})`);
      assert.equal(mode(app.dbPath()) & 0o077, 0, `the database must be owner-only (is ${mode(app.dbPath()).toString(8)})`);
      assert.equal(mode(app.logPath()) & 0o077, 0, `the log must be owner-only (is ${mode(app.logPath()).toString(8)})`);
    } finally {
      await app.stop();
    }
  });
});
