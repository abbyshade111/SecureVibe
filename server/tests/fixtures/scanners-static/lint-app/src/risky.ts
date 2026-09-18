// Fixture: a few eslint-plugin-security findings, plus one pattern (object indexing) the recommended
// config would normally flag through detect-object-injection — CONTRACTS §3 turns that rule off.
import { exec } from 'node:child_process';
import crypto from 'node:crypto';

export function run(cmd: string): void {
  exec(cmd);
}

export function weakRandom(): Buffer {
  return crypto.pseudoRandomBytes(16);
}

export const BAD_REGEX = /^(a+)+$/;

export function readObj(key: string, obj: Record<string, unknown>): unknown {
  return obj[key];
}
