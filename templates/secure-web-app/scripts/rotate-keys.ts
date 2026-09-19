/**
 * Replaces the app's session key and token key with fresh ones.
 *
 * Why it exists: a key that never changes is a key that is still good years after a laptop is lost or a backup
 * goes astray. Rotating regularly is half of what "secrets are managed properly" means, and it is the half an
 * app can do for itself whatever it is hosted on.
 *
 * What it costs, said plainly because the script does it immediately: everyone signed in is signed out, and any
 * unused password-reset or invitation link stops working. Nobody's data is touched and no password changes.
 *
 * The field-encryption key is not rotated here: that one re-encrypts stored data and has its own script,
 * `npm run rotate:field-key`, which must be run while the old key is still present.
 *
 * Only works when the secrets live in the .env file (the default). If SECRETS_SOURCE names a host's store, that
 * store is the place to rotate them, and this script says so rather than writing a file the app will not read.
 */
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROTATES = ['SESSION_SECRET', 'TOKEN_HMAC_KEY'] as const;

export function newSecret(): string {
  return randomBytes(48).toString('base64');
}

/** Rewrites only the named keys, leaving every other line — and every comment — exactly as it was. */
export function replaceEnvValues(text: string, values: Record<string, string>): string {
  const lines = text.split(/\r?\n/);
  const seen = new Set<string>();
  const out = lines.map((line) => {
    const eq = line.indexOf('=');
    if (line.trim().startsWith('#') || eq <= 0) return line;
    const key = line.slice(0, eq).trim();
    const value = values[key];
    if (value === undefined) return line;
    seen.add(key);
    return `${key}=${value}`;
  });
  for (const [key, value] of Object.entries(values)) if (!seen.has(key)) out.push(`${key}=${value}`);
  return out.join('\n');
}

export function rotateEnvFile(file: string): { rotated: string[] } {
  if (!existsSync(file)) throw new Error(`${file} is not there, so there is nothing to rotate.`);
  const values: Record<string, string> = {};
  for (const name of ROTATES) values[name] = newSecret();
  writeFileSync(file, replaceEnvValues(readFileSync(file, 'utf8'), values), { mode: 0o600 });
  chmodSync(file, 0o600);
  return { rotated: [...ROTATES] };
}

async function main(): Promise<void> {
  const source = (process.env['SECRETS_SOURCE'] ?? 'env').trim();
  if (source !== 'env') {
    console.error(
      `This app reads its secrets from ${source === 'files' ? 'a folder of files' : 'a command'} (SECRETS_SOURCE=${source}), not from .env.\n` +
        `Rotate ${ROTATES.join(' and ')} where they are actually kept, then restart the app.`,
    );
    process.exitCode = 1;
    return;
  }
  const file = resolve(fileURLToPath(new URL('..', import.meta.url)), '.env');
  const { rotated } = rotateEnvFile(file);
  console.log(`Rotated ${rotated.join(' and ')}.`);
  console.log('Everyone signed in has been signed out, and unused password-reset and invitation links no longer work.');
  console.log('No data was touched and nobody needs to change their password. Start the app again to pick up the new keys.');
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
