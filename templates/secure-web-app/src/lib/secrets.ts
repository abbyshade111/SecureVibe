/**
 * Where this app's secrets come from.
 *
 * The default is the `.env` file beside the app, with strict file permissions — which is right for an app running
 * on one person's computer, and is what SecureVibe sets up. Somewhere with more than one machine or more than one
 * operator, secrets belong in whatever that place already uses: a hosting provider's secret manager, Docker
 * secrets, systemd credentials, an encrypted file decrypted at deploy time.
 *
 * This is the seam that makes those possible without touching a line of application code. It fills the
 * environment before `loadConfig` reads it, and nothing downstream knows or cares where a value came from.
 *
 * What it deliberately is not: a secret manager. Running one beside the app would mean a service to unseal, back
 * up and keep alive, whose own credential ends up in a file on the same disk with the same permissions as the
 * `.env` it replaced — indirection sold as protection. See docs/adr/0002-secrets.md.
 *
 * Values already in the environment always win, so a host that injects real environment variables needs nothing
 * here at all.
 *
 * There is deliberately no "run this command to fetch them" source, though it is the obvious third option. It
 * would make every app built by SecureVibe start an operating-system command at boot, which widens what any bug
 * in the app can reach — and SecureVibe's own scanner said so, raising two high findings against this file when
 * it had one. Tools like sops and Vault are normally used to produce an environment or a file before the process
 * starts (`sops exec-env`, a Vault agent writing a template), so nothing is lost: do that, and point SECRETS_DIR
 * here, or let them export real environment variables.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export type SecretsSource = 'env' | 'files';

/** A name a secret may have. Anything else in the source is ignored rather than trusted. */
const SECRET_NAME = /^[A-Z][A-Z0-9_]*$/;

export interface SecretsOptions {
  source?: string;
  dir?: string;
  /** Present for tests; the real one is the process environment. */
  target?: NodeJS.ProcessEnv;
}

export interface SecretsLoaded {
  source: SecretsSource;
  /** Names only — never values, and never logged as anything else. */
  names: string[];
  note: string;
}

/**
 * One file per secret, named after it: the shape Docker secrets (/run/secrets) and systemd credentials
 * ($CREDENTIALS_DIRECTORY) both use, so neither needs an adapter.
 */
function fromFiles(dir: string, target: NodeJS.ProcessEnv): string[] {
  if (!existsSync(dir)) throw new Error(`SECRETS_DIR is set to ${dir}, which does not exist. The app will not start without its secrets.`);
  const taken: string[] = [];
  for (const name of readdirSync(dir)) {
    if (!SECRET_NAME.test(name)) continue;
    const file = join(dir, name);
    if (!statSync(file).isFile()) continue;
    if (target[name] !== undefined) continue;
    // Trailing newlines are what an editor or `echo` leaves behind, and a secret never ends in whitespace.
    target[name] = readFileSync(file, 'utf8').replace(/\r?\n$/, '');
    taken.push(name);
  }
  return taken;
}

/**
 * Fills `target` from the configured source. Call before reading the configuration. Returns the names it
 * supplied, for the startup log; the values are never returned, printed or logged.
 */
export function loadSecrets(opts: SecretsOptions = {}): SecretsLoaded {
  const target = opts.target ?? process.env;
  const source = (opts.source ?? target['SECRETS_SOURCE'] ?? 'env').trim() as SecretsSource;
  if (source === 'env') {
    return { source, names: [], note: 'Secrets come from the environment and the .env file beside the app.' };
  }
  if (source === 'files') {
    const dir = (opts.dir ?? target['SECRETS_DIR'] ?? '').trim();
    if (!dir) throw new Error('SECRETS_SOURCE=files needs SECRETS_DIR to say which folder holds them.');
    const names = fromFiles(dir, target);
    return { source, names, note: `Secrets come from one file each in ${dir}.` };
  }
  throw new Error(`SECRETS_SOURCE must be "env" or "files"; it is "${String(source)}".`);
}
