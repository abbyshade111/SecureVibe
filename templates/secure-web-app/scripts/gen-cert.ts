/**
 * Creates a self-signed certificate for TLS_MODE=selfsigned (certs/key.pem and certs/cert.pem) using the
 * `openssl` command when it is installed. Browsers will warn about a self-signed certificate; that is expected
 * on a private network. For anything reachable from the internet use a real certificate (see docs/deployment.md).
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CERTS_DIR = resolve(APP_ROOT, 'certs');
const KEY_FILE = resolve(CERTS_DIR, 'key.pem');
const CERT_FILE = resolve(CERTS_DIR, 'cert.pem');
const DAYS = 825;

function hostArg(): string {
  const i = process.argv.indexOf('--host');
  const host = i >= 0 ? (process.argv[i + 1] ?? '') : 'localhost';
  if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) {
    process.stderr.write('The --host value must be a plain host name such as myapp.local.\n');
    process.exit(1);
  }
  return host;
}

if (existsSync(KEY_FILE) && existsSync(CERT_FILE) && !process.argv.includes('--force')) {
  process.stdout.write('certs/key.pem and certs/cert.pem already exist. Run again with --force to replace them.\n');
  process.exit(0);
}

const which = spawnSync('openssl', ['version'], { encoding: 'utf8' });
if (which.error || which.status !== 0) {
  process.stderr.write(
    [
      '',
      'The "openssl" command was not found, so the certificate cannot be created here.',
      'Options:',
      '  - Install OpenSSL (macOS: it ships with the system or via Homebrew; Windows: install Git for Windows, which includes it; Linux: your package manager).',
      '  - Or create certs/key.pem and certs/cert.pem with another tool such as mkcert.',
      '',
    ].join('\n'),
  );
  process.exit(1);
}

mkdirSync(CERTS_DIR, { recursive: true, mode: 0o700 });
const host = hostArg();
// Fixed arguments only; the host name is validated above and never interpolated into a shell.
const result = spawnSync(
  'openssl',
  ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', KEY_FILE, '-out', CERT_FILE, '-days', String(DAYS), '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host},DNS:localhost,IP:127.0.0.1`],
  { encoding: 'utf8' },
);
if (result.status !== 0) {
  process.stderr.write(`\nopenssl could not create the certificate.\n${result.stderr}\n`);
  process.exit(1);
}
chmodSync(KEY_FILE, 0o600);
chmodSync(CERT_FILE, 0o644);
process.stdout.write(`Created ${KEY_FILE} and ${CERT_FILE} for ${host} (valid ${DAYS} days).\nSet TLS_MODE=selfsigned in .env and restart the app. Browsers will show a warning for a self-signed certificate.\n`);
