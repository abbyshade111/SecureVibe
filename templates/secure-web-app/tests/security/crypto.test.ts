/** Cryptography and secrets (TPL-CRYPTO-01, TPL-SECRETS-01, contract §1.2 field-crypto, §1.3). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { b64, expectStartupRefusal, runScript, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';
import { templateRoot } from '../helpers/features.ts';
import { totp, waitForFreshStep } from '../helpers/totp.ts';

const ENCRYPTED = /^v(\d+):([A-Za-z0-9+/=_-]+):([A-Za-z0-9+/=_-]+):([A-Za-z0-9+/=_-]*)$/;

function placeholderFor(variable: string): string {
  const example = join(templateRoot, '.env.example');
  if (existsSync(example)) {
    const m = readFileSync(example, 'utf8').match(new RegExp(`^${variable}=(.*)$`, 'm'));
    if (m && m[1]!.trim() !== '') return m[1]!.trim().replace(/^["']|["']$/g, '');
  }
  return 'change-me-change-me-change-me-change-me-change-me';
}

describe('crypto', () => {
  let app: RunningApp;
  let memberSeed: string | undefined;
  let seedColumn: string | undefined;

  before(async () => {
    // Field encryption is checked on a TOTP seed, so a member must be able to enrol whatever this app offers its users.
    app = await startApp({ env: { USER_MFA_AVAILABLE: '1' } });
  });
  after(async () => {
    await app?.stop();
  });

  async function enrolMember(): Promise<string> {
    const jar = await app.login(users.member);
    const re = await app.reauth(jar);
    await re.text();
    const { res, html } = await app.page(paths.mfaEnrol, jar);
    assert.equal(res.status, 200, `enrol page answered ${res.status}`);
    const secret = html.match(/secret=([A-Z2-7]+)/i)?.[1];
    assert.ok(secret, 'enrol page must show the TOTP secret');
    await waitForFreshStep();
    const confirm = await app.submitForm(paths.mfaConfirm, { [fields.code]: totp(secret) }, jar, { csrfFrom: paths.mfaEnrol });
    const body = await confirm.text();
    assert.ok(confirm.status < 400, `enrolment failed: ${confirm.status} ${body.slice(0, 200)}`);
    return secret;
  }

  test('V11.3.2 sensitive fields are encrypted at rest with AES-256-GCM in the versioned v<key>:iv:tag:ciphertext format', async () => {
    memberSeed = await enrolMember();
    const row = app.userByEmail(users.member)!;
    seedColumn = Object.keys(row).find((c) => /totp|mfa|otp/i.test(c) && /secret|seed|key/i.test(c));
    assert.ok(seedColumn, `no TOTP seed column in users: ${Object.keys(row).join(', ')}`);
    const stored = String(row[seedColumn]);
    const m = stored.match(ENCRYPTED);
    assert.ok(m, `stored seed is not in the v<keyId>:iv:tag:ciphertext format: ${stored.slice(0, 40)}`);
    assert.equal(m[1], app.env.ACTIVE_FIELD_KEY ?? '1', 'the active key id must be used');
    const iv = Buffer.from(m[2]!, m[2]!.includes('-') || m[2]!.includes('_') ? 'base64url' : 'base64');
    const tag = Buffer.from(m[3]!, m[3]!.includes('-') || m[3]!.includes('_') ? 'base64url' : 'base64');
    assert.equal(iv.length, 12, 'GCM nonce must be 96 bits');
    assert.equal(tag.length, 16, 'GCM authentication tag must be 128 bits');
    assert.equal(app.dbContains(memberSeed), false, 'the seed must not be stored in clear');
    const admin = app.userByEmail(users.admin)!;
    assert.match(String(admin[seedColumn]), ENCRYPTED, "the seeded admin's secret must also be encrypted");
    assert.notEqual(m[2], String(admin[seedColumn]).match(ENCRYPTED)?.[2], 'nonces must be unique per value');
  });

  test('V11.3.3 authenticated encryption: a tampered ciphertext is rejected instead of decrypted', async () => {
    assert.ok(memberSeed && seedColumn, 'depends on the encryption test above');
    const row = app.userByEmail(users.member)!;
    const stored = String(row[seedColumn!]);
    const parts = stored.split(':');
    const ct = parts[3]!;
    const flipped = ct.slice(0, -2) + (ct.slice(-2) === 'AA' ? 'BB' : 'AA');
    parts[3] = flipped;
    app.dbRun(`UPDATE users SET ${seedColumn} = ? WHERE lower(email) = lower(?)`, parts.join(':'), users.member);
    await waitForFreshStep();
    const loggedIn = await app.canLogin(users.member, app.password, memberSeed);
    assert.equal(loggedIn, false, 'a tampered ciphertext must not decrypt to a working seed');
    const tagParts = stored.split(':');
    tagParts[2] = tagParts[2]!.slice(0, -2) + (tagParts[2]!.slice(-2) === 'AA' ? 'BB' : 'AA');
    app.dbRun(`UPDATE users SET ${seedColumn} = ? WHERE lower(email) = lower(?)`, tagParts.join(':'), users.member);
    assert.equal(await app.canLogin(users.member, app.password, memberSeed), false, 'a tampered authentication tag must be rejected');
    app.dbRun(`UPDATE users SET ${seedColumn} = ? WHERE lower(email) = lower(?)`, stored, users.member);
    await waitForFreshStep();
    assert.equal(await app.canLogin(users.member, app.password, memberSeed), true, 'the original ciphertext must still work');
  });

  test('V11.2.2 crypto agility: keys are versioned, a new active key is used for new data and old data can be rotated', async () => {
    assert.ok(memberSeed && seedColumn, 'depends on the encryption test above');
    const key2 = b64(32);
    const env2 = { ...app.env, FIELD_KEYS: `${app.env.FIELD_KEYS},2:${key2}`, ACTIVE_FIELD_KEY: '2' };
    const dataDir = app.dataDir;
    // Keep the database so the restarted instance sees data encrypted under key 1.
    await app.stop({ keepDataDir: true });
    const restarted = await startApp({ dataDir, env: env2 });
    try {
      // Old data (encrypted under key 1) still decrypts.
      assert.equal(await restarted.canLogin(users.member, restarted.password, memberSeed), true, 'data encrypted under key 1 must still decrypt with key 2 active');
      const before = String(restarted.userByEmail(users.member)![seedColumn!]);
      assert.match(before, /^v1:/);
      // New data uses the active key.
      const jar = await restarted.login(users.member2);
      const re = await restarted.reauth(jar);
      await re.text();
      const { html } = await restarted.page(paths.mfaEnrol, jar);
      const secret = html.match(/secret=([A-Z2-7]+)/i)?.[1];
      assert.ok(secret);
      await waitForFreshStep();
      const confirm = await restarted.submitForm(paths.mfaConfirm, { [fields.code]: totp(secret) }, jar, { csrfFrom: paths.mfaEnrol });
      await confirm.text();
      assert.match(String(restarted.userByEmail(users.member2)![seedColumn!]), /^v2:/, 'new values must be encrypted with the active key');
      // Rotation re-encrypts old rows under the active key.
      const rotate = await runScript('rotate-field-key', restarted.env);
      assert.equal(rotate.code, 0, `rotate-field-key failed: ${rotate.stderr || rotate.stdout}`);
      assert.match(String(restarted.userByEmail(users.member)![seedColumn!]), /^v2:/, 'rotation must re-encrypt existing rows with the active key');
      await waitForFreshStep();
      assert.equal(await restarted.canLogin(users.member, restarted.password, memberSeed), true, 'rotated data must still decrypt');
    } finally {
      await restarted.stop();
      rmSync(dataDir, { recursive: true, force: true });
      app = await startApp();
    }
  });

  test('V13.2.3 placeholder or weak secrets are refused at startup with a message naming the variable', async () => {
    const cases: [string, string][] = [
      ['SESSION_SECRET', placeholderFor('SESSION_SECRET')],
      ['SESSION_SECRET', b64(16)],
      ['SESSION_SECRET', ''],
      ['TOKEN_HMAC_KEY', placeholderFor('TOKEN_HMAC_KEY')],
      ['TOKEN_HMAC_KEY', b64(20)],
      ['FIELD_KEYS', placeholderFor('FIELD_KEYS')],
      ['FIELD_KEYS', `1:${b64(16)}`],
    ];
    for (const [variable, value] of cases) {
      const result = await expectStartupRefusal({ [variable]: value });
      assert.notEqual(result.code, 0, `${variable}=${value.slice(0, 12)}... must be refused`);
      const output = `${result.stdout}\n${result.stderr}`;
      assert.ok(output.includes(variable), `the startup message must name ${variable}: ${output.slice(0, 400)}`);
      assert.doesNotMatch(output, /at .*\.ts:\d+/, 'a configuration error must be a plain message, not a stack trace');
      if (value !== '') assert.equal(output.includes(value), false, 'the refused secret value must not be echoed');
    }
    const example = join(templateRoot, '.env.example');
    assert.ok(existsSync(example), '.env.example must exist');
    const text = readFileSync(example, 'utf8');
    for (const variable of ['SESSION_SECRET', 'FIELD_KEYS', 'TOKEN_HMAC_KEY']) assert.match(text, new RegExp(`^${variable}=`, 'm'), `.env.example must document ${variable}`);
    assert.doesNotMatch(text, /ANTHROPIC_API_KEY=sk-ant-/, '.env.example must not contain a real API key');
  });

  test('V11.2.1 only approved primitives: no MD5/SHA-1 for security purposes and no Math.random in security code', async () => {
    const { readdirSync, statSync } = await import('node:fs');
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full);
        else if (full.endsWith('.ts')) {
          const src = readFileSync(full, 'utf8');
          if (/createHash\(\s*['"](md5|sha1)['"]\s*\)/.test(src) && !full.endsWith('totp.ts')) offenders.push(`${full}: weak hash`);
          if (/Math\.random\(/.test(src)) offenders.push(`${full}: Math.random`);
          if (/createCipher\(|createDecipher\(/.test(src)) offenders.push(`${full}: deprecated createCipher`);
          if (/from\s+['"](bcrypt|md5|sha1|crypto-js|node-forge)['"]/.test(src)) offenders.push(`${full}: third-party crypto`);
        }
      }
    };
    walk(join(templateRoot, 'src', 'security'));
    walk(join(templateRoot, 'src', 'db'));
    walk(join(templateRoot, 'src', 'lib'));
    assert.deepEqual(offenders, [], `non-approved cryptography in security code:\n${offenders.join('\n')}`);
  });
});
