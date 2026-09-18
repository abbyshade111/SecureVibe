/** RFC 6238 TOTP (HMAC-SHA1, 30 s step, 6 digits) and RFC 4648 base32, using only node:crypto. */
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

export function base32Decode(str: string): Buffer {
  const clean = str.toUpperCase().replace(/=+$/, '').replace(/[\s-]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function randomTotpSeed(): string {
  return base32Encode(randomBytes(20));
}

/** Steps a code has already been generated for, per seed, so freshTotp() never presents the same code twice. */
const handedOutSteps = new Map<string, Set<number>>();

function rememberStep(seedBase32: string, counter: number): void {
  const steps = handedOutSteps.get(seedBase32) ?? new Set<number>();
  steps.add(counter);
  handedOutSteps.set(seedBase32, steps);
}

export interface TotpOptions {
  step?: number;
  digits?: number;
  /** Number of steps to shift from `now` (negative = past). */
  offset?: number;
  now?: number;
}

export function totp(seedBase32: string, opts: TotpOptions = {}): string {
  const step = opts.step ?? 30;
  const digits = opts.digits ?? 6;
  const now = opts.now ?? Date.now();
  const counter = Math.floor(now / 1000 / step) + (opts.offset ?? 0);
  // Remember which steps have been turned into codes so freshTotp() never hands out one of them again.
  rememberStep(seedBase32, counter);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32Decode(seedBase32)).update(msg).digest();
  const off = digest[digest.length - 1]! & 0x0f;
  const bin =
    ((digest[off]! & 0x7f) << 24) | ((digest[off + 1]! & 0xff) << 16) | ((digest[off + 2]! & 0xff) << 8) | (digest[off + 3]! & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** Milliseconds until the current 30 s TOTP step ends. */
export function msUntilNextStep(step = 30, now = Date.now()): number {
  const stepMs = step * 1000;
  return stepMs - (now % stepMs);
}

/** Waits until at least `minRemainingMs` remain in the current step so a code computed now stays valid. */
export async function waitForFreshStep(minRemainingMs = 12_000): Promise<void> {
  const remaining = msUntilNextStep();
  if (remaining < minRemainingMs) await new Promise((r) => setTimeout(r, remaining + 200));
}

/**
 * Waits until the next step has begun. A code computed afterwards belongs to a step that was never presented
 * before, which `waitForFreshStep` alone does not guarantee (it only asks for enough time left in the current
 * step, which may already have been used).
 */
export async function waitForNextStep(step = 30): Promise<void> {
  await new Promise((r) => setTimeout(r, msUntilNextStep(step) + 250));
}

/**
 * A TOTP code for a step that no code has been generated for yet (for this seed), waiting for the next step when
 * needed. The app accepts each step only once per account (replay prevention, V6.5.1), so a test that signs the
 * same account in twice within 30 seconds must present a code from a later step.
 */
export async function freshTotp(seedBase32: string, step = 30): Promise<string> {
  for (;;) {
    const current = Math.floor(Date.now() / 1000 / step);
    // Leave enough of the step for the request to arrive while the code is still current.
    if (!handedOutSteps.get(seedBase32)?.has(current) && msUntilNextStep(step) > 1_000) return totp(seedBase32, { step });
    await waitForNextStep(step);
  }
}
