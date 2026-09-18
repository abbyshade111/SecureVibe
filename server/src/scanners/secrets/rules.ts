/**
 * Secret-detection rules (CONTRACTS §4): regex patterns for well-known credential formats plus a
 * Shannon-entropy heuristic for anything else that looks like a real secret. Each rule scans raw file
 * text and returns the byte offsets of what it found; `index.ts` turns those into Findings.
 */
import { looksLikePlaceholder, SECRET_ENV_NAME, SECRET_NAME, shannonEntropy } from '../sast/rules/base.js';
import type { RuleMeta } from '../sast/findings.js';

export interface SecretMatch {
  /** Character offset into the scanned text. */
  index: number;
  /** The matched secret text (redacted before it reaches a Finding). */
  value: string;
  /** Folded into the fingerprint so two different secrets on the same line stay distinct findings. */
  fingerprintExtra?: string;
}

export interface SecretRuleDef {
  meta: RuleMeta;
  /** Whether this rule is still meaningful to run against `.env` (most are not — see index.ts). */
  scanEnvFiles: boolean;
  scan(text: string): SecretMatch[];
}

function fromGlobalRegex(re: RegExp, text: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = g.exec(text)) !== null) {
    out.push({ index: m.index, value: m[0] });
    if (m[0].length === 0) g.lastIndex++;
  }
  return out;
}

function meta(input: Omit<RuleMeta, 'remediation' | 'whoCanFix'> & { fix: string; steps?: string[]; references?: string[] }): RuleMeta {
  const { fix, steps, references, ...rest } = input;
  return { ...rest, remediation: { summary: fix, steps: steps ?? [], references: references ?? [] } };
}

// ---------------------------------------------------------------------------------------------
// Known-format credentials

export const anthropicKey: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.anthropic-key',
    title: 'Anthropic API key found in a file',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-798', 'CWE-540'],
    asvs: ['V13.3.1'],
    aisvs: ['C9.5.4'],
    sbd: ['AC-05'],
    exploitability: 'trivial',
    description: 'A string starting with sk-ant- (an Anthropic API key) appears in a file.',
    impact: 'Anyone with the file can spend money on your account and read anything sent to the model.',
    fix: 'Revoke the key in the Anthropic console, issue a new one, and keep it only in .env.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/sk-ant-[A-Za-z0-9_-]{20,}/g, text),
};

export const awsAccessKey: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.aws-access-key',
    title: 'AWS access key ID found in a file',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'trivial',
    description: 'A string shaped like an Amazon Web Services access key id (AKIA...) appears in a file.',
    impact: 'Combined with its secret key it gives access to your cloud account.',
    fix: 'Deactivate the key in AWS IAM and load credentials from the environment instead.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, text),
};

export const awsSecretKey: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.aws-secret-key',
    title: 'AWS secret access key found in a file',
    severity: 'critical',
    confidence: 'medium',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'trivial',
    description: 'A 40-character AWS secret access key is assigned to a variable named like an AWS credential.',
    impact: 'Gives full use of the paired access key — access to your cloud account.',
    fix: 'Deactivate the key pair in AWS IAM and load new credentials from the environment.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) =>
    fromGlobalRegex(/\b(?:aws[_-]?secret(?:[_-]?access)?[_-]?key|secret[_-]?access[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9/+]{40})['"]?/gi, text).map((m) => ({
      ...m,
      value: /['"]?([A-Za-z0-9/+]{40})['"]?$/.exec(m.value)?.[1] ?? m.value,
    })),
};

export const githubToken: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.github-token',
    title: 'GitHub token found in a file',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'trivial',
    description: 'A GitHub personal access token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_) appears in a file.',
    impact: 'Grants access to your repositories, possibly with write permission.',
    fix: 'Revoke the token on GitHub and, if still needed, create a new one with minimum scopes stored in .env.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/\bgh[oprsu]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, text),
};

export const slackToken: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.slack-token',
    title: 'Slack token found in a file',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'trivial',
    description: 'A Slack token (xoxb-/xoxp-/xoxa-/xoxr-/xapp-) appears in a file.',
    impact: 'Lets an attacker read or post messages in your Slack workspace as your app or user.',
    fix: 'Revoke the token in Slack and issue a new one stored in .env only.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/\bxox[baprs]-[A-Za-z0-9-]{10,48}\b/g, text),
};

export const stripeKey: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.stripe-key',
    title: 'Stripe key found in a file',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05', 'AC-06'],
    exploitability: 'trivial',
    description: 'A Stripe key (sk_live_/sk_test_/rk_live_) appears in a file.',
    impact: 'A live secret key can create charges and refunds on your Stripe account.',
    fix: 'Roll the key in the Stripe dashboard and keep the new one in .env only.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g, text),
};

export const googleApiKey: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.google-api-key',
    title: 'Google API key found in a file',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'trivial',
    description: 'A Google API key (AIza...) appears in a file.',
    impact: 'Can run up charges on your Google Cloud account and use whatever APIs the key is enabled for.',
    fix: 'Regenerate the key in Google Cloud Console, restrict it, and store it in .env only.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/\bAIza[0-9A-Za-z_-]{35}\b/g, text),
};

export const privateKeyBlock: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.private-key-block',
    title: 'Private key found in a file',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-321'],
    asvs: ['V11.1.1', 'V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'requires-network-exposure',
    description: "A '-----BEGIN ... PRIVATE KEY-----' block appears outside the certs/ folder.",
    impact: 'A private key lets an attacker impersonate your server or decrypt its traffic.',
    fix: 'Remove the key from the file, regenerate it, and keep private keys only in certs/ with restrictive permissions.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, text),
};

export const jwt: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.jwt',
    title: 'JSON Web Token found in a file',
    severity: 'medium',
    confidence: 'medium',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'theoretical',
    description: 'A string shaped like a JSON Web Token (eyJ....eyJ....xxxx) appears in a file.',
    impact: 'It may be a valid access token for a service; whoever has it can act as its owner until it expires.',
    fix: 'Remove the token from the file. Generate tokens at test/run time instead of committing them.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => fromGlobalRegex(/\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, text),
};

export const connectionStringPassword: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.connection-string-password',
    title: 'Connection string contains a password',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'theoretical',
    description: 'A database or service URL of the form scheme://user:password@host appears in a file.',
    impact: 'Exposes the credentials for that service to anyone who can read the file.',
    fix: 'Move the connection string to .env, read it through config, and change the password.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) =>
    fromGlobalRegex(/\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s'"/:@]+:[^\s'"/:@]+@[^\s'")]+/gi, text).filter((m) => {
      const parts = /^[^:]+:\/\/([^:]+):([^@]+)@/.exec(m.value);
      if (!parts) return true;
      const [, user = '', pass = ''] = parts;
      // Documentation syntax ([user:pass@]) and placeholder credentials are not real secrets.
      if (/[[\]]/.test(m.value)) return false;
      return !(looksLikePlaceholder(pass) || /^(pass|pw|pwd|user)$/i.test(pass) || (/^user(name)?$/i.test(user) && pass.length < 8));
    }),
};

// ---------------------------------------------------------------------------------------------
// Heuristic rules: literal secrets assigned to a suspicious name

const ASSIGNMENT = /([A-Za-z_][A-Za-z0-9_.]{0,60})\s*[:=]\s*['"]([^'"\n]{1,400})['"]/g;
/** `.env`-style `KEY=value` (no quotes, no trailing comment). */
const ENV_ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=([^\n#]*)$/gm;

function* assignments(text: string): Iterable<{ name: string; value: string; index: number; valueIndex: number }> {
  for (const m of text.matchAll(ASSIGNMENT)) {
    const value = m[2] ?? '';
    yield { name: m[1] ?? '', value, index: m.index, valueIndex: m.index + m[0].lastIndexOf(value) };
  }
  for (const m of text.matchAll(ENV_ASSIGNMENT)) {
    const value = (m[2] ?? '').trim();
    if (!value) continue;
    yield { name: m[1] ?? '', value, index: m.index, valueIndex: m.index + m[0].indexOf(value, m[1]!.length) };
  }
}

export const highEntropyAssignment: SecretRuleDef = {
  scanEnvFiles: false, // .env is expected to hold real, high-entropy generated secrets; see index.ts
  meta: meta({
    id: 'secrets.high-entropy-assignment',
    title: 'Random-looking value assigned to a secret-like name',
    severity: 'medium',
    confidence: 'medium',
    cwe: ['CWE-798'],
    asvs: ['V13.3.1'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'theoretical',
    description: 'A long, random-looking string is assigned to a variable named like key, secret, token or password.',
    impact: 'It is probably a real credential written into the code, where anyone with the code can read it.',
    fix: 'Move the value to .env and read it through config; rotate it if it was a real credential.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => {
    const out: SecretMatch[] = [];
    for (const a of assignments(text)) {
      if (!SECRET_NAME.test(a.name) && !SECRET_ENV_NAME.test(a.name)) continue;
      if (a.value.length < 20 || looksLikePlaceholder(a.value)) continue;
      if (!/^[A-Za-z0-9+/=_.-]+$/.test(a.value)) continue; // real secrets are base64/hex/url-safe, not sentences
      if (shannonEntropy(a.value) < 4.0) continue;
      out.push({ index: a.valueIndex, value: a.value, fingerprintExtra: a.name });
    }
    return out;
  },
};

export const passwordAssignment: SecretRuleDef = {
  scanEnvFiles: false,
  meta: meta({
    id: 'secrets.password-assignment',
    title: 'Password written in a file',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-259'],
    asvs: ['V13.3.1', 'V13.2.3'],
    aisvs: [],
    sbd: ['AC-05'],
    exploitability: 'theoretical',
    description: 'A variable named password (or similar) is assigned a literal value.',
    impact: 'The password is visible to anyone with the code and cannot be changed without editing it.',
    fix: 'Remove the literal; read the value from .env, or generate it at setup time. Change the account password.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  }),
  scan: (text) => {
    const out: SecretMatch[] = [];
    const PASSWORD_NAME = /^(password|passwd|pwd)$/i;
    for (const a of assignments(text)) {
      if (!PASSWORD_NAME.test(a.name.replace(/^.*\./, ''))) continue;
      if (a.value.length === 0 || looksLikePlaceholder(a.value)) continue;
      // A sentence ("Your password is not correct.") is a message shown to a person, not a stored password.
      if (a.value.trim().split(/\s+/).length >= 3) continue;
      out.push({ index: a.valueIndex, value: a.value, fingerprintExtra: a.name });
    }
    return out;
  },
};

export const contentRules: SecretRuleDef[] = [
  anthropicKey,
  awsAccessKey,
  awsSecretKey,
  githubToken,
  slackToken,
  stripeKey,
  googleApiKey,
  privateKeyBlock,
  jwt,
  connectionStringPassword,
  highEntropyAssignment,
  passwordAssignment,
];

export const envFileCommittedMeta: RuleMeta = meta({
  id: 'secrets.env-file-committed',
  title: '.env is inside a git repository',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-540'],
  asvs: ['V13.3.1'],
  aisvs: [],
  sbd: ['AC-05'],
  exploitability: 'theoretical',
  description: 'A .env file sits next to a .git folder and .gitignore does not exclude it.',
  impact: 'Every secret in .env becomes part of the repository history, readable by anyone with access.',
  fix: 'Add .env and .env.* to .gitignore, remove .env from git history if it was committed, then regenerate secrets.',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
});
