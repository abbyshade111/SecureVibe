/**
 * RFC 6238 one-time codes for the fixture app, so the DAST harness can complete the administrator's second
 * sign-in step from the seed it passed in SECUREVIBE_TEST_TOTP_SEED.
 */
import { createHmac } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/=+$/, '').replace(/[\s-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
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

export function totp(seedBase32, offset = 0, now = Date.now()) {
  const counter = Math.floor(now / 30000) + offset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32Decode(seedBase32)).update(msg).digest();
  const off = digest[digest.length - 1] & 0x0f;
  const bin =
    ((digest[off] & 0x7f) << 24) | ((digest[off + 1] & 0xff) << 16) | ((digest[off + 2] & 0xff) << 8) | (digest[off + 3] & 0xff);
  return String(bin % 1000000).padStart(6, '0');
}

/** Accepts the current code and the ones either side of it (clock drift), as RFC 6238 suggests. */
export function verifyTotp(seedBase32, code) {
  if (!seedBase32 || !/^\d{6}$/.test(String(code ?? ''))) return false;
  for (const offset of [-1, 0, 1]) {
    if (totp(seedBase32, offset) === String(code)) return true;
  }
  return false;
}
