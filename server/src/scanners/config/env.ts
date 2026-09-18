/**
 * A minimal `.env` parser: good enough for the config checks, not a general-purpose library.
 * Supports `KEY=value`, `KEY="quoted value"`, blank lines and `#` comments.
 */
export function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

/** Decoded byte length of a base64/base64url string; NaN when it does not look like base64 at all. */
export function base64ByteLength(value: string): number {
  const cleaned = value.trim();
  if (cleaned.length === 0 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(cleaned)) return NaN;
  try {
    return Buffer.from(cleaned, 'base64').length;
  } catch {
    return NaN;
  }
}
