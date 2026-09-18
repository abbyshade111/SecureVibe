/**
 * RFC 6238 time-based one-time passwords over node:crypto (HMAC-SHA1, 30-second step, 6 digits) and RFC 4648
 * base32, so the harness can complete the admin's second sign-in step from the seed it handed the app.
 */
import { createHmac, randomBytes } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/=+$/, '').replace(/[\s-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function randomTotpSeed(): string {
  return base32Encode(randomBytes(20));
}

export interface TotpOptions {
  step?: number;
  digits?: number;
  /** Steps to shift from `now` (negative = past). */
  offset?: number;
  now?: number;
}

export function totp(seedBase32: string, opts: TotpOptions = {}): string {
  const step = opts.step ?? 30;
  const digits = opts.digits ?? 6;
  const now = opts.now ?? Date.now();
  const counter = Math.floor(now / 1000 / step) + (opts.offset ?? 0);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32Decode(seedBase32)).update(msg).digest();
  const off = (digest[digest.length - 1] ?? 0) & 0x0f;
  const bin =
    (((digest[off] ?? 0) & 0x7f) << 24) |
    (((digest[off + 1] ?? 0) & 0xff) << 16) |
    (((digest[off + 2] ?? 0) & 0xff) << 8) |
    ((digest[off + 3] ?? 0) & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** Milliseconds until the current step ends (used to avoid submitting a code that is about to expire). */
export function msUntilNextStep(step = 30, now = Date.now()): number {
  const stepMs = step * 1000;
  return stepMs - (now % stepMs);
}
