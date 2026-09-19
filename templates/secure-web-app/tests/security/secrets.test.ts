/**
 * Where the app's secrets come from (V14.2.1, AC-05 in part).
 *
 * The .env file stays the default. This covers the seam that lets a host's own store supply them instead, so
 * moving to one is configuration rather than a code change — and, just as importantly, that a misconfigured
 * source stops the app rather than letting it start with no secrets or with the wrong ones.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadSecrets } from '../../src/lib/secrets.ts';

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'secrets-'));
}

describe('where secrets come from', () => {
  test('V14.2.1 the default is the environment and the .env file, and it touches nothing', () => {
    const target: NodeJS.ProcessEnv = { EXISTING: 'kept' };
    const loaded = loadSecrets({ target });
    assert.equal(loaded.source, 'env');
    assert.deepEqual(target, { EXISTING: 'kept' });
  });

  test('V14.2.1 a folder of files supplies secrets, one file per name', () => {
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

  test('V14.2.1 a value already in the environment always wins, so a host that injects one needs nothing here', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'SESSION_SECRET'), 'from-a-file');
    const target: NodeJS.ProcessEnv = { SESSION_SECRET: 'from-the-host' };
    loadSecrets({ source: 'files', dir, target });
    assert.equal(target['SESSION_SECRET'], 'from-the-host');
  });

  test('V14.2.1 anything that is not a secret name is ignored rather than trusted', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'lowercase'), 'no');
    writeFileSync(join(dir, '..sneaky'), 'no');
    mkdirSync(join(dir, 'SUBFOLDER'));
    const target: NodeJS.ProcessEnv = {};
    const loaded = loadSecrets({ source: 'files', dir, target });
    assert.deepEqual(loaded.names, []);
    assert.deepEqual(Object.keys(target), []);
  });

  test('V14.2.1 a command can supply them, for a host store or an encrypted file', () => {
    const dir = tempDir();
    const script = join(dir, 'print-secrets.sh');
    writeFileSync(script, '#!/bin/sh\necho "SESSION_SECRET=from-a-command"\necho "# a comment"\necho "not a line"\n');
    chmodSync(script, 0o700);
    const target: NodeJS.ProcessEnv = {};
    const loaded = loadSecrets({ source: 'command', command: script, target });
    assert.equal(target['SESSION_SECRET'], 'from-a-command');
    assert.deepEqual(loaded.names, ['SESSION_SECRET']);
  });

  test('V14.2.1 a source that cannot be read stops the app rather than starting it without secrets', () => {
    assert.throws(() => loadSecrets({ source: 'files', dir: join(tempDir(), 'not-there'), target: {} }), /does not exist/);
    assert.throws(() => loadSecrets({ source: 'files', target: {} }), /SECRETS_DIR/);
    assert.throws(() => loadSecrets({ source: 'command', target: {} }), /SECRETS_COMMAND/);
    assert.throws(() => loadSecrets({ source: 'nonsense', target: {} }), /must be/);
  });

  test('V14.2.1 a failing command never puts its output in the error, because the output is the secret', () => {
    const dir = tempDir();
    const script = join(dir, 'fail.sh');
    writeFileSync(script, '#!/bin/sh\necho "SESSION_SECRET=leaked-into-stdout"\nexit 3\n');
    chmodSync(script, 0o700);
    try {
      loadSecrets({ source: 'command', command: script, target: {} });
      assert.fail('a failing command should stop the app');
    } catch (err) {
      assert.doesNotMatch((err as Error).message, /leaked-into-stdout/);
    }
  });
});
