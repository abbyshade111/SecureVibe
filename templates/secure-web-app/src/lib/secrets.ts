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
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export type SecretsSource = 'env' | 'files' | 'command';

/** A name a secret may have. Anything else in the source is ignored rather than trusted. */
const SECRET_NAME = /^[A-Z][A-Z0-9_]*$/;

export interface SecretsOptions {
  source?: string;
  dir?: string;
  command?: string;
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
 * A command that prints KEY=value lines: `sops -d secrets.env`, `vault kv get -format=...`, a wrapper around a
 * cloud provider's manager. Run once at startup, before the app listens, and its output is never logged.
 */
function fromCommand(command: string, target: NodeJS.ProcessEnv): string[] {
  const parts = command.trim().split(/\s+/);
  const file = parts[0];
  if (!file) throw new Error('SECRETS_COMMAND is empty.');
  let out: string;
  try {
    out = execFileSync(file, parts.slice(1), { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  } catch (err) {
    // The message may carry part of the command's output, which may carry a secret.
    throw new Error(`SECRETS_COMMAND failed after ${(err as { signal?: string }).signal === 'SIGTERM' ? 'timing out' : 'exiting with an error'}. The app will not start without its secrets.`);
  }
  const taken: string[] = [];
  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const name = line.slice(0, eq).trim();
    if (!SECRET_NAME.test(name)) continue;
    if (target[name] !== undefined) continue;
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    target[name] = value;
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
  if (source === 'command') {
    const command = (opts.command ?? target['SECRETS_COMMAND'] ?? '').trim();
    if (!command) throw new Error('SECRETS_SOURCE=command needs SECRETS_COMMAND to say what to run.');
    const names = fromCommand(command, target);
    return { source, names, note: 'Secrets come from the command in SECRETS_COMMAND.' };
  }
  throw new Error(`SECRETS_SOURCE must be "env", "files" or "command"; it is "${String(source)}".`);
}
