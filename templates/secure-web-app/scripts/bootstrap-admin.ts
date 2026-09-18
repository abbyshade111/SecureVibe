/**
 * Creates the first administrator account with a random one-time password. The password is printed once and
 * written to FIRST-LOGIN.txt in the current folder (mode 0600); only its hash is stored. The account must change
 * the password at first sign-in, and the one-time password stops working after 24 hours if unused.
 *
 *   node --experimental-strip-types scripts/bootstrap-admin.ts [--email owner@example.com] [--force]
 *
 * Without --force the script refuses to add an administrator when one already exists (use the app instead).
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../src/config.ts';
import { openDb, closeDb } from '../src/db/index.ts';
import { runMigrations } from '../src/db/migrate.ts';
import { countAdmins, createUser, findUserByEmail } from '../src/features/auth/repo.ts';
import { emit } from '../src/security/events.ts';
import { generateOneTimePassword, hashPassword } from '../src/security/password.ts';

export const BOOTSTRAP_EXPIRY_HOURS = 24;

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function isEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

export interface BootstrapResult {
  email: string;
  password: string;
  expiresAt: string;
  file: string;
}

export async function bootstrapAdmin(options: { email?: string; force?: boolean; outDir?: string; noForceChange?: boolean }): Promise<BootstrapResult> {
  const email = (options.email ?? config.ADMIN_EMAIL ?? config.design.profile?.deployment?.owner?.contactEmail ?? 'admin@localhost.localdomain').trim().toLowerCase();
  if (!isEmail(email)) throw new Error(`"${email}" does not look like an email address. Pass one with --email you@example.com.`);
  openDb();
  runMigrations();
  if (findUserByEmail(email)) throw new Error(`An account for ${email} already exists. Use "Forgotten your password?" in the app to reset it.`);
  if (countAdmins() > 0 && !options.force) {
    throw new Error('An administrator account already exists. Invite further administrators from the app, or run again with --force to add one anyway.');
  }
  const password = generateOneTimePassword();
  const expiresAt = new Date(Date.now() + BOOTSTRAP_EXPIRY_HOURS * 3_600_000).toISOString();
  // A SecureVibe app preview skips the "choose your own password" step: the account and its data are thrown away.
  const mustChangePassword = options.noForceChange !== true;
  const user = createUser({ email, name: null, passwordHash: await hashPassword(password), role: config.adminRole, mustChangePassword, bootstrapExpiresAt: expiresAt });
  emit('admin.user.created', { userId: user.id, targetUserId: user.id, role: config.adminRole, by: 'bootstrap-admin' });
  const file = resolve(options.outDir ?? process.cwd(), 'FIRST-LOGIN.txt');
  const text = [
    `First sign-in for ${config.appName}`,
    '',
    `Email address: ${email}`,
    `One-time password: ${password}`,
    '',
    `Sign in once with this password before ${expiresAt.slice(0, 16).replace('T', ' ')} UTC, then choose your own.`,
    'The app will ask you to change it straight away and to set up one-time codes with an authenticator app.',
    'Delete this file once you have signed in.',
    '',
  ].join('\n');
  writeFileSync(file, text, { mode: 0o600 });
  return { email, password, expiresAt, file };
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain && process.argv.includes('--check')) {
  // Used by setup.ts to decide whether the administrator step is still needed.
  openDb();
  runMigrations();
  process.stdout.write(countAdmins() > 0 ? 'exists\n' : 'none\n');
  closeDb();
} else if (isMain) {
  bootstrapAdmin({ email: argValue('--email'), force: process.argv.includes('--force'), noForceChange: process.argv.includes('--no-force-change') })
    .then((result) => {
      process.stdout.write(
        [
          '',
          `Administrator account created: ${result.email}`,
          `One-time password: ${result.password}`,
          `It expires at ${result.expiresAt.slice(0, 16).replace('T', ' ')} UTC and must be changed at first sign-in.`,
          `Also saved to ${result.file} (delete it after signing in).`,
          '',
        ].join('\n'),
      );
      closeDb();
    })
    .catch((err: Error) => {
      process.stderr.write(`\nCould not create the administrator account.\n${err.message}\n\n`);
      closeDb();
      process.exit(1);
    });
}
