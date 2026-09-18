/**
 * Synchronous password hashing used only by the test-mode seeder (which runs inside a transaction and cannot
 * await). Produces the same PHC strings as security/password.ts so verifyPassword() accepts them.
 */
import * as crypto from 'node:crypto';
import { ARGON2_PARAMS, SCRYPT_PARAMS } from '../security/password.ts';

type Argon2SyncFn = (
  algorithm: 'argon2id',
  params: { message: Buffer; nonce: Buffer; parallelism: number; tagLength: number; memory: number; passes: number },
) => Buffer;

const argon2Sync = (crypto as unknown as { argon2Sync?: Argon2SyncFn }).argon2Sync;

function b64(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '');
}

export function hashPasswordSync(password: string): string {
  const salt = crypto.randomBytes(16);
  const message = Buffer.from(password, 'utf8');
  if (argon2Sync) {
    const out = argon2Sync('argon2id', { message, nonce: salt, ...ARGON2_PARAMS });
    return `$argon2id$v=19$m=${ARGON2_PARAMS.memory},t=${ARGON2_PARAMS.passes},p=${ARGON2_PARAMS.parallelism}$${b64(salt)}$${b64(out)}`;
  }
  const out = crypto.scryptSync(message, salt, SCRYPT_PARAMS.keylen, { N: SCRYPT_PARAMS.N, r: SCRYPT_PARAMS.r, p: SCRYPT_PARAMS.p, maxmem: 256 * 1024 * 1024 });
  return `$scrypt$ln=${Math.log2(SCRYPT_PARAMS.N)},r=${SCRYPT_PARAMS.r},p=${SCRYPT_PARAMS.p}$${b64(salt)}$${b64(out)}`;
}
