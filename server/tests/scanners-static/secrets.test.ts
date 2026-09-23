/**
 * Secrets scanner (CONTRACTS §4): every `secrets.*` rule id fires at least once, and `.env` is excluded
 * from the content rules (it is expected to hold real generated secrets) but still checked for being
 * next to an uninitialised `.git` repository without `.gitignore` coverage.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { redact, runSecrets, SECRETS_TOOL } from '../../src/scanners/secrets/index.js';
import { fixtureDir, makeScanContext } from './helpers.js';
import { connectionStringPassword, passwordAssignment } from '../../src/scanners/secrets/rules.js';

const ALL_SECRET_RULE_IDS = [
  'secrets.anthropic-key',
  'secrets.aws-access-key',
  'secrets.aws-secret-key',
  'secrets.github-token',
  'secrets.slack-token',
  'secrets.stripe-key',
  'secrets.google-api-key',
  'secrets.private-key-block',
  'secrets.jwt',
  'secrets.high-entropy-assignment',
  'secrets.password-assignment',
  'secrets.connection-string-password',
  'secrets.env-file-committed',
];

// `secrets.env-file-committed` only fires for a .env sitting beside a .git folder, so this fixture needs one.
// Git refuses to track any path under a directory named .git, so it cannot be committed and has only ever
// existed on the machine that first created it. On a clean checkout the rule fired nowhere, and the test below
// reported it as a rule that never fires - green here, red on every runner, for as long as the workflow has
// existed. Creating it here makes the fixture say what it needs out loud instead of inheriting it.
beforeAll(() => {
  const gitDir = join(fixtureDir('secrets-app'), '.git');
  mkdirSync(gitDir, { recursive: true });
  writeFileSync(join(gitDir, 'HEAD'), '', 'utf8');
});

describe('redact', () => {
  it('shows only the first 4 and last 2 characters of a matched secret', () => {
    expect(redact('sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBe('sk-a************AA');
  });

  it('never reveals a short value outright', () => {
    const out = redact('abcdef');
    expect(out).not.toContain('abcdef');
  });
});

describe('secrets scanner', () => {
  it('finds every secrets.* rule at least once in the fixture app', async () => {
    const ctx = makeScanContext(fixtureDir('secrets-app'));
    const result = await runSecrets(ctx);
    const found = new Set(result.findings.map((f) => f.ruleId));
    const missing = ALL_SECRET_RULE_IDS.filter((id) => !found.has(id));
    expect(missing).toEqual([]);
  });

  it('reports the exact rule → location table', async () => {
    const ctx = makeScanContext(fixtureDir('secrets-app'));
    const result = await runSecrets(ctx);
    const byRuleAndLine = (ruleId: string, file: string, line: number): boolean =>
      result.findings.some((f) => f.ruleId === ruleId && f.location?.file === file && f.location?.line === line);

    expect(byRuleAndLine('secrets.anthropic-key', 'src/config-leak.ts', 3)).toBe(true);
    expect(byRuleAndLine('secrets.aws-access-key', 'src/config-leak.ts', 4)).toBe(true);
    expect(byRuleAndLine('secrets.aws-secret-key', 'src/config-leak.ts', 5)).toBe(true);
    expect(byRuleAndLine('secrets.github-token', 'src/config-leak.ts', 6)).toBe(true);
    expect(byRuleAndLine('secrets.slack-token', 'src/config-leak.ts', 7)).toBe(true);
    expect(byRuleAndLine('secrets.stripe-key', 'src/config-leak.ts', 8)).toBe(true);
    expect(byRuleAndLine('secrets.google-api-key', 'src/config-leak.ts', 9)).toBe(true);
    expect(byRuleAndLine('secrets.connection-string-password', 'src/config-leak.ts', 10)).toBe(true);
    expect(byRuleAndLine('secrets.jwt', 'src/config-leak.ts', 11)).toBe(true);
    expect(byRuleAndLine('secrets.high-entropy-assignment', 'src/config-leak.ts', 12)).toBe(true);
    expect(byRuleAndLine('secrets.password-assignment', 'src/config-leak.ts', 13)).toBe(true);
    expect(byRuleAndLine('secrets.private-key-block', 'src/leaked-key.txt', 3)).toBe(true);
    expect(byRuleAndLine('secrets.env-file-committed', '.env', 1)).toBe(true);
  });

  it('never puts the full secret value in a finding, only a redacted snippet and evidence', async () => {
    const ctx = makeScanContext(fixtureDir('secrets-app'));
    const result = await runSecrets(ctx);
    for (const f of result.findings) {
      expect(JSON.stringify(f)).not.toContain('AAAAAAAAAAAAAAAAAAAAAAAAAAAA'); // the fixture Anthropic key body
      expect(JSON.stringify(f)).not.toContain('Sup3rSecretPass'); // the fixture connection-string password
    }
  });

  it('does not scan .env with the credential-pattern rules (real generated secrets live there)', async () => {
    const ctx = makeScanContext(fixtureDir('secrets-app'));
    const result = await runSecrets(ctx);
    const envContentFindings = result.findings.filter((f) => f.location?.file === '.env' && f.ruleId !== 'secrets.env-file-committed');
    expect(envContentFindings).toEqual([]);
  });

  it('raises nothing for ordinary code without secrets', async () => {
    const ctx = makeScanContext(fixtureDir('secrets-app'));
    const result = await runSecrets(ctx);
    expect(result.findings.some((f) => f.location?.file === 'src/no-secrets-here.ts')).toBe(false);
  });

  it('every finding is source "secrets" with the tool name and a stable fingerprint', async () => {
    const ctx = makeScanContext(fixtureDir('secrets-app'));
    const result = await runSecrets(ctx);
    for (const f of result.findings) {
      expect(f.source).toBe('secrets');
      expect(f.tool?.name).toBe(SECRETS_TOOL.name);
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    }
  });
});

describe('secrets rules ignore text that only looks like a credential', () => {
  it('skips documentation syntax and placeholder credentials in connection strings', () => {
    expect(connectionStringPassword.scan('/** `smtp://[user:pass@]host[:port]` */')).toEqual([]);
    expect(connectionStringPassword.scan("parseSmtpUrl('smtp://user:pass@mail.example.com:2525')")).toEqual([]);
    expect(connectionStringPassword.scan("const url = 'postgres://app:Sup3rSecretPass@db.internal:5432/app'")).toHaveLength(1);
  });

  it('skips messages shown to people but still flags a literal password', () => {
    expect(passwordAssignment.scan("errors: { password: 'Your password is not correct.' }")).toEqual([]);
    expect(passwordAssignment.scan("const password = 'Tuesday-Morning-42';")).toHaveLength(1);
  });
});
