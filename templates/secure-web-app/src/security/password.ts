/**
 * Password policy and hashing.
 *  - Policy: 12 to 256 characters, no composition rules, exact match (nothing is trimmed), not in the common
 *    password list, and not containing the app name, the user's name or the email's local part.
 *  - Hashing: argon2id (m=65536, t=3, p=4) through Node's built-in crypto.argon2 when the runtime has it, otherwise
 *    scrypt (N=131072, r=8, p=1, 64-byte key). Both are stored as PHC strings and both can be verified.
 *  - Tokens: reset/invite tokens are 16 random bytes; only HMAC-SHA256(TOKEN_HMAC_KEY, token) is stored.
 */
import * as crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { APP_ROOT, config } from '../config.ts';
import { all } from '../db/index.ts';

export const MIN_LENGTH = 12;
export const MAX_LENGTH = 256;
export const COMMON_PASSWORDS_FILE = resolve(APP_ROOT, 'data', 'common-passwords.txt');

export const ARGON2_PARAMS = { memory: 65536, passes: 3, parallelism: 4, tagLength: 32 } as const;
export const SCRYPT_PARAMS = { N: 131072, r: 8, p: 1, keylen: 64 } as const;

type Argon2Fn = (
  algorithm: 'argon2id',
  params: { message: Buffer; nonce: Buffer; parallelism: number; tagLength: number; memory: number; passes: number },
  callback: (err: Error | null, out: Buffer) => void,
) => void;

const nativeArgon2 = (crypto as unknown as { argon2?: Argon2Fn }).argon2;
const argon2Async = nativeArgon2 ? promisify(nativeArgon2) : undefined;
const scryptAsync = promisify(crypto.scrypt) as (
  password: Buffer,
  salt: Buffer,
  keylen: number,
  options: crypto.ScryptOptions,
) => Promise<Buffer>;

export type HashAlgorithm = 'argon2id' | 'scrypt';

export function activeAlgorithm(): HashAlgorithm {
  return argon2Async ? 'argon2id' : 'scrypt';
}

let commonPasswords: Set<string> | undefined;

export function loadCommonPasswords(file: string = COMMON_PASSWORDS_FILE): Set<string> {
  if (commonPasswords) return commonPasswords;
  const set = new Set<string>();
  if (existsSync(file)) {
    for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
      const value = line.trim().toLowerCase();
      if (value) set.add(value);
    }
  }
  commonPasswords = set;
  return set;
}

export interface PasswordContext {
  email?: string | null;
  name?: string | null;
  appName?: string;
}

export interface PolicyResult {
  ok: boolean;
  /** Plain-language reason shown to the user when `ok` is false. */
  reason?: string;
}

function contextWords(ctx: PasswordContext): string[] {
  const words = new Set<string>();
  const add = (v: string | null | undefined) => {
    if (!v) return;
    for (const part of v.toLowerCase().split(/[^a-z0-9]+/)) if (part.length >= 4) words.add(part);
    const whole = v.toLowerCase().trim();
    if (whole.length >= 4) words.add(whole);
  };
  add(ctx.appName ?? config.appName);
  add(ctx.name);
  if (ctx.email) add(ctx.email.split('@')[0]);
  return [...words];
}

export function checkPasswordPolicy(password: string, ctx: PasswordContext = {}): PolicyResult {
  if (typeof password !== 'string') return { ok: false, reason: 'Please enter a password.' };
  if (password.length < MIN_LENGTH) return { ok: false, reason: `Your password must be at least ${MIN_LENGTH} characters long. A short sentence works well.` };
  if (password.length > MAX_LENGTH) return { ok: false, reason: `Your password must be at most ${MAX_LENGTH} characters long.` };
  if (loadCommonPasswords().has(password.toLowerCase())) {
    return { ok: false, reason: 'That password is on the list of commonly used passwords, so attackers try it first. Please choose a different one.' };
  }
  const lower = password.toLowerCase();
  for (const word of contextWords(ctx)) {
    if (lower.includes(word)) {
      return { ok: false, reason: 'Your password must not contain your name, your email address or the name of this app.' };
    }
  }
  return { ok: true };
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const message = Buffer.from(password, 'utf8');
  if (argon2Async) {
    const out = await argon2Async('argon2id', { message, nonce: salt, ...ARGON2_PARAMS });
    return `$argon2id$v=19$m=${ARGON2_PARAMS.memory},t=${ARGON2_PARAMS.passes},p=${ARGON2_PARAMS.parallelism}$${b64(salt)}$${b64(out)}`;
  }
  const out = await scryptAsync(message, salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: 256 * 1024 * 1024,
  });
  return `$scrypt$ln=${Math.log2(SCRYPT_PARAMS.N)},r=${SCRYPT_PARAMS.r},p=${SCRYPT_PARAMS.p}$${b64(salt)}$${b64(out)}`;
}

function b64(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '');
}

function parsePhc(phc: string): { algorithm: HashAlgorithm; params: Record<string, number>; salt: Buffer; hash: Buffer } | undefined {
  const parts = phc.split('$');
  if (parts.length < 5 || parts[0] !== '') return undefined;
  const algorithm = parts[1];
  const params: Record<string, number> = {};
  let paramIndex = 2;
  if (algorithm === 'argon2id') paramIndex = 3; // skip v=19
  const paramText = parts[paramIndex] ?? '';
  for (const kv of paramText.split(',')) {
    const [k, v] = kv.split('=');
    if (k && v !== undefined) params[k] = Number(v);
  }
  const salt = parts[paramIndex + 1];
  const hash = parts[paramIndex + 2];
  if (!salt || !hash) return undefined;
  if (algorithm !== 'argon2id' && algorithm !== 'scrypt') return undefined;
  return { algorithm, params, salt: Buffer.from(salt, 'base64'), hash: Buffer.from(hash, 'base64') };
}

export function hashAlgorithmOf(phc: string): HashAlgorithm | undefined {
  return parsePhc(phc)?.algorithm;
}

export async function verifyPassword(password: string, phc: string): Promise<boolean> {
  const parsed = parsePhc(phc);
  if (!parsed) return false;
  const message = Buffer.from(password, 'utf8');
  let computed: Buffer;
  if (parsed.algorithm === 'argon2id') {
    if (!argon2Async) throw new Error('This account was protected with argon2id but this Node.js runtime cannot verify argon2id hashes.');
    computed = await argon2Async('argon2id', {
      message,
      nonce: parsed.salt,
      memory: parsed.params['m'] ?? ARGON2_PARAMS.memory,
      passes: parsed.params['t'] ?? ARGON2_PARAMS.passes,
      parallelism: parsed.params['p'] ?? ARGON2_PARAMS.parallelism,
      tagLength: parsed.hash.length,
    });
  } else {
    const ln = parsed.params['ln'] ?? 17;
    const N = 2 ** ln;
    const r = parsed.params['r'] ?? 8;
    computed = await scryptAsync(message, parsed.salt, parsed.hash.length, {
      N,
      r,
      p: parsed.params['p'] ?? 1,
      maxmem: Math.max(256 * 1024 * 1024, 128 * N * r * 2),
    });
  }
  if (computed.length !== parsed.hash.length) return false;
  return crypto.timingSafeEqual(computed, parsed.hash);
}

let dummyHash: string | undefined;

/** Verifies against a throw-away hash so unknown accounts cost the same time as wrong passwords. */
export async function dummyVerify(password: string): Promise<void> {
  if (!dummyHash) dummyHash = await hashPassword(crypto.randomBytes(24).toString('base64url'));
  await verifyPassword(password, dummyHash);
}

/** Refuses to start when a stored hash uses an algorithm this runtime cannot verify (argon2id hashes on a scrypt-only Node). */
export function assertStoredHashesSupported(): void {
  if (argon2Async) return;
  const rows = all<{ password_hash: string }>("SELECT password_hash FROM users WHERE password_hash LIKE '$argon2id$%' LIMIT 1");
  if (rows.length > 0) {
    throw new Error(
      'Stored passwords use argon2id but this Node.js version has no built-in argon2. Start the app with the same or a newer Node.js version.',
    );
  }
}

/** 16 random bytes, base64url — used for password reset links and invitations. */
export function createOpaqueToken(bytes = 16): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Keyed hash for tokens and API keys stored at rest. */
export function hmacToken(token: string): string {
  return crypto.createHmac('sha256', Buffer.from(config.TOKEN_HMAC_KEY, 'base64')).update(token).digest('hex');
}

/** Random one-time password for bootstrap/admin-created accounts (16 bytes → 22 characters). */
export function generateOneTimePassword(): string {
  return crypto.randomBytes(16).toString('base64url');
}

export function hashEmailForLogs(email: string): string {
  return crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex').slice(0, 12);
}
