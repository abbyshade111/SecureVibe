/**
 * Writes `.env` with strong random secrets. Safe to run again: an existing `.env` keeps every value that is
 * already set; only missing values and the example placeholders are filled in. Nothing is printed except a
 * summary — the secrets themselves stay in the file (mode 0600).
 *
 * This script deliberately does not import src/config.ts: config refuses to load while secrets are missing,
 * which is exactly the situation this script fixes.
 */
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENV_FILE = resolve(APP_ROOT, '.env');
const EXAMPLE_FILE = resolve(APP_ROOT, '.env.example');
const PLACEHOLDER = '__generate_with_npm_run_setup__';

const SECRET_GENERATORS: Record<string, () => string> = {
  SESSION_SECRET: () => randomBytes(32).toString('base64'),
  TOKEN_HMAC_KEY: () => randomBytes(32).toString('base64'),
  FIELD_KEYS: () => `1:${randomBytes(32).toString('base64')}`,
};

function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return v === '' || v.includes(PLACEHOLDER) || /^(changeme|change-me|replace-me|secret|password)$/i.test(v);
}

/** Returns the lines of the file with each secret line rewritten when needed. */
export function fillSecrets(lines: string[]): { lines: string[]; generated: string[] } {
  const generated: string[] = [];
  const seen = new Set<string>();
  const out = lines.map((line) => {
    const m = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
    if (!m) return line;
    const [, key, value] = m;
    if (!key || !(key in SECRET_GENERATORS)) return line;
    seen.add(key);
    if (!isPlaceholder(value ?? '')) return line;
    generated.push(key);
    return `${key}=${SECRET_GENERATORS[key]!()}`;
  });
  for (const key of Object.keys(SECRET_GENERATORS)) {
    if (seen.has(key)) continue;
    generated.push(key);
    out.push(`${key}=${SECRET_GENERATORS[key]!()}`);
  }
  return { lines: out, generated };
}

export function generateSecrets(): { created: boolean; generated: string[] } {
  const created = !existsSync(ENV_FILE);
  const source = created ? (existsSync(EXAMPLE_FILE) ? readFileSync(EXAMPLE_FILE, 'utf8') : '') : readFileSync(ENV_FILE, 'utf8');
  const { lines, generated } = fillSecrets(source.split(/\r?\n/));
  if (created || generated.length > 0) {
    writeFileSync(ENV_FILE, lines.join('\n').replace(/\n*$/, '\n'), { mode: 0o600 });
  }
  chmodSync(ENV_FILE, 0o600);
  return { created, generated };
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const result = generateSecrets();
  if (result.created) process.stdout.write('Created .env from .env.example with fresh secrets.\n');
  else if (result.generated.length > 0) process.stdout.write(`Filled in missing secrets in .env: ${result.generated.join(', ')}.\n`);
  else process.stdout.write('.env already has all its secrets; nothing changed.\n');
  process.stdout.write('Keep .env private. It is listed in .gitignore and must never be shared.\n');
}
