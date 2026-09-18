/**
 * Time-based one-time passwords (RFC 6238) built on node:crypto only: HMAC-SHA1 over a 30-second counter,
 * 6 digits, one step of tolerance either way, and replay prevention (a step can only be used once).
 * Recovery codes: 10 codes of 10 base32 characters, stored hashed, single use.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { hmacToken } from './password.ts';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_WINDOW = 1;
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODE_LENGTH = 10;

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** 20 random bytes (160 bits), the size RFC 4226 recommends for HMAC-SHA1. */
export function generateTotpSecret(): Buffer {
  return randomBytes(20);
}

export function currentStep(now: number = Date.now()): number {
  return Math.floor(now / 1000 / TOTP_STEP_SECONDS);
}

export function totpForStep(secret: Buffer, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac('sha1', secret).update(counter).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) | ((digest[offset + 1]! & 0xff) << 16) | ((digest[offset + 2]! & 0xff) << 8) | (digest[offset + 3]! & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

export function totpNow(secret: Buffer, now: number = Date.now()): string {
  return totpForStep(secret, currentStep(now));
}

export interface TotpVerification {
  ok: boolean;
  /** The step that matched; the caller records it with `rememberUsedStep` so the same code cannot be replayed. */
  step?: number;
  reason?: 'format' | 'mismatch' | 'replay';
}

/**
 * Checks a 6-digit code against the current step and one step either side. A step that was already accepted
 * (`usedSteps`) is refused, so a captured code cannot be replayed while it is still within the window, while an
 * unused code from the neighbouring step (clock drift) is still accepted.
 */
export function verifyTotp(secret: Buffer, code: string, usedSteps: readonly number[], now: number = Date.now()): TotpVerification {
  const normalised = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalised)) return { ok: false, reason: 'format' };
  const step = currentStep(now);
  let matchedStep: number | undefined;
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta += 1) {
    const candidate = step + delta;
    const expected = totpForStep(secret, candidate);
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(normalised)) && matchedStep === undefined) matchedStep = candidate;
  }
  if (matchedStep === undefined) return { ok: false, reason: 'mismatch' };
  if (usedSteps.includes(matchedStep)) return { ok: false, reason: 'replay' };
  return { ok: true, step: matchedStep };
}

/** Adds a step to the used list and drops steps that can no longer be presented (older than the window). */
export function rememberUsedStep(usedSteps: readonly number[], step: number, now: number = Date.now()): number[] {
  const oldest = currentStep(now) - TOTP_WINDOW - 1;
  return [...usedSteps.filter((s) => s >= oldest && s !== step), step].slice(-8);
}

export function otpauthUrl(issuer: string, account: string, secret: Buffer): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${base32Encode(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}

export function generateRecoveryCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i += 1) {
    codes.push(base32Encode(randomBytes(10)).slice(0, RECOVERY_CODE_LENGTH));
  }
  return codes;
}

export function normaliseRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[^A-Z2-7]/g, '');
}

export function hashRecoveryCode(code: string): string {
  return hmacToken(`recovery:${normaliseRecoveryCode(code)}`);
}

/** Recovery codes are shown as XXXXX-XXXXX for easier copying. */
export function formatRecoveryCode(code: string): string {
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}
