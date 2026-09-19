/**
 * Where the app's secrets come from.
 *
 * Deliberately no requirement id on these test names. V14.2.1, which they carried at first, is about sensitive
 * data in URLs and query strings — nothing to do with this; SecureVibe's own misnamed-test screen caught that,
 * which is the check working. The requirement this is nearest to, V13.3.1, asks for a secrets management
 * solution, and a seam plus a manual rotation command is not one. A test with no id claims nothing, which is the
 * honest answer: this is hardening, not the control.
 *
 * Which is also why it sits here rather than in tests/security/, where every test name must begin with a
 * requirement id — a rule worth keeping, since that is how a test becomes evidence for a requirement. The app
 * still runs this file: the test runner walks the whole tests folder.
 *
 * The .env file stays the default. This covers the seam that lets a host's own store supply them instead, so
 * moving to one is configuration rather than a code change — and, just as importantly, that a misconfigured
 * source stops the app rather than letting it start with no secrets or with the wrong ones.
 */
import { after, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { loadSecrets } from '../src/lib/secrets.ts';

/**
 * Under DATA_DIR, which is the only place these tests may write.
 *
 * A generated app runs its tests under Node's permission model, and that fence allows reading anywhere in the
 * app folder but writing only to the data folder. The system temp folder is refused, and so is the app folder
 * itself — my first two attempts at this used one each. The template's own suite passed both times, because it
 * does not run behind the fence, while every app SecureVibe built had four failing tests.
 */
const made: string[] = [];
function tempDir(): string {
  const root = process.env['DATA_DIR'] ?? join(import.meta.dirname, '..', 'data');
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, 'secrets-test-'));
  made.push(dir);
  return dir;
}

after(() => {
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

describe('where secrets come from', () => {
  test('the default is the environment and the .env file, and it touches nothing', () => {
    const target: NodeJS.ProcessEnv = { EXISTING: 'kept' };
    const loaded = loadSecrets({ target });
    assert.equal(loaded.source, 'env');
    assert.deepEqual(target, { EXISTING: 'kept' });
  });

  test('a folder of files supplies secrets, one file per name', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'SESSION_SECRET'), 'from-a-file\n');
    writeFileSync(join(dir, 'TOKEN_HMAC_KEY'), 'another');
    const target: NodeJS.ProcessEnv = {};
    const loaded = loadSecrets({ source: 'files', dir, target });
    // The trailing newline an editor leaves behind is not part of the secret.
    assert.equal(target['SESSION_SECRET'], 'from-a-file');
    assert.equal(target['TOKEN_HMAC_KEY'], 'another');
    assert.deepEqual(loaded.names.sort(), ['SESSION_SECRET', 'TOKEN_HMAC_KEY']);
  });

  test('a value already in the environment always wins, so a host that injects one needs nothing here', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'SESSION_SECRET'), 'from-a-file');
    const target: NodeJS.ProcessEnv = { SESSION_SECRET: 'from-the-host' };
    loadSecrets({ source: 'files', dir, target });
    assert.equal(target['SESSION_SECRET'], 'from-the-host');
  });

  test('anything that is not a secret name is ignored rather than trusted', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'lowercase'), 'no');
    writeFileSync(join(dir, '..sneaky'), 'no');
    mkdirSync(join(dir, 'SUBFOLDER'));
    const target: NodeJS.ProcessEnv = {};
    const loaded = loadSecrets({ source: 'files', dir, target });
    assert.deepEqual(loaded.names, []);
    assert.deepEqual(Object.keys(target), []);
  });

  test('a source that cannot be read stops the app rather than starting it without secrets', () => {
    assert.throws(() => loadSecrets({ source: 'files', dir: join(tempDir(), 'not-there'), target: {} }), /does not exist/);
    assert.throws(() => loadSecrets({ source: 'files', target: {} }), /SECRETS_DIR/);
    assert.throws(() => loadSecrets({ source: 'nonsense', target: {} }), /must be/);
  });

  test('there is no "run a command" source, so the app never starts a program to fetch its secrets', () => {
    // The obvious third source would have every app built by SecureVibe run an operating-system command at boot,
    // widening what any bug in the app can reach. SecureVibe's own scanner raised two high findings against this
    // file when it had one. Tools like sops and Vault produce an environment or a file before the process starts,
    // so nothing is lost by refusing.
    assert.throws(() => loadSecrets({ source: 'command', target: {} }), /must be "env" or "files"/);
    const source = readFileSync(new URL('../src/lib/secrets.ts', import.meta.url), 'utf8');
    assert.doesNotMatch(source, /child_process|execFile|execSync|spawn/);
  });
});
