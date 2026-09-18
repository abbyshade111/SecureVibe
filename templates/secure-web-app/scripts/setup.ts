/**
 * First-run setup, in order: generate secrets (.env), create the database and apply migrations, create the first
 * administrator. Each step runs in its own process so the configuration is read only after the secrets exist.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function runStep(label: string, script: string, args: string[] = []): void {
  process.stdout.write(`\n== ${label}\n`);
  const result = spawnSync(process.execPath, ['--experimental-strip-types', resolve(APP_ROOT, 'scripts', script), ...args], {
    cwd: APP_ROOT,
    stdio: 'inherit',
    env: process.env,
  });
  if (result.status !== 0) {
    process.stderr.write(`\nSetup stopped at "${label}". Fix the problem above and run "npm run setup" again.\n`);
    process.exit(result.status ?? 1);
  }
}

function adminExists(): boolean {
  // The admin step refuses to run twice; skipping it keeps "npm run setup" safe to repeat.
  const dataDir = process.env['DATA_DIR'] ?? readEnvValue('DATA_DIR') ?? './data';
  const dbFile = resolve(APP_ROOT, dataDir, 'app.sqlite');
  if (!existsSync(dbFile)) return false;
  const probe = spawnSync(process.execPath, ['--experimental-strip-types', resolve(APP_ROOT, 'scripts', 'bootstrap-admin.ts'), '--check'], { cwd: APP_ROOT, env: process.env, encoding: 'utf8' });
  return probe.status === 0 && /exists/.test(probe.stdout + probe.stderr);
}

function readEnvValue(key: string): string | undefined {
  const file = resolve(APP_ROOT, '.env');
  if (!existsSync(file)) return undefined;
  const m = readFileSync(file, 'utf8').match(new RegExp(`^${key}=(.*)$`, 'm'));
  return m?.[1]?.trim() || undefined;
}

runStep('Secrets', 'gen-secrets.ts');
runStep('Database', 'migrate.ts');
const emailArgs = process.argv.includes('--email') ? ['--email', process.argv[process.argv.indexOf('--email') + 1] ?? ''] : [];
if (adminExists()) {
  process.stdout.write('\n== Administrator\nAn administrator account already exists; nothing to do. Use "Forgotten your password?" in the app if you cannot sign in.\n');
} else {
  runStep('Administrator', 'bootstrap-admin.ts', emailArgs);
}
process.stdout.write('\nSetup complete. Start the app with:  npm start\n\n');
