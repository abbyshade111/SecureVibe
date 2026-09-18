/**
 * Redirects only ever go to local paths. A "next" value from a form or query string that points anywhere else
 * (another site, a protocol-relative URL, a path with line breaks or control characters) is replaced by the
 * fallback. Percent-escapes are decoded before the check, so a target such as `/%2F%2Fevil.example` — which
 * decodes to the protocol-relative `///evil.example` and is resolved that way by some proxies and clients —
 * is refused just like the form it decodes to.
 */
import type { Response } from 'express';

/** One leading slash, no second slash or backslash (protocol-relative), printable ASCII only: no spaces, no control characters. */
const LOCAL_PATH = /^\/(?![/\\])[!-[\]-~]*$/;
/** "/javascript:" style tricks. */
const SCHEME_LIKE = /^\/[^/?#]*:/;
const MAX_LENGTH = 500;
const MAX_DECODE_ROUNDS = 3;

function looksLocal(value: string): boolean {
  if (!LOCAL_PATH.test(value)) return false;
  if (SCHEME_LIKE.test(value)) return false;
  if (value.startsWith('/__securevibe')) return false;
  return true;
}

/** Returns `target` when it is a safe local path (optionally within an allow-list of prefixes), otherwise `fallback`. */
export function safeLocalPath(target: unknown, allowList?: readonly string[], fallback = '/'): string {
  if (typeof target !== 'string') return fallback;
  if (target.length > MAX_LENGTH) return fallback;
  let candidate = target;
  for (let round = 0; round < MAX_DECODE_ROUNDS; round += 1) {
    if (!looksLocal(candidate)) return fallback;
    let decoded: string;
    try {
      decoded = decodeURIComponent(candidate);
    } catch {
      return fallback; // malformed percent-escapes are never a safe redirect target
    }
    if (decoded === candidate) break;
    candidate = decoded;
  }
  if (!looksLocal(candidate)) return fallback;
  if (allowList && !allowList.some((prefix) => target === prefix || target.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`) || target.startsWith(`${prefix}?`))) {
    return fallback;
  }
  return target;
}

/** Redirects to a validated local path. Returns the path actually used. */
export function safeRedirect(res: Response, target: unknown, allowList?: readonly string[], fallback = '/'): string {
  const path = safeLocalPath(target, allowList, fallback);
  res.redirect(303, path);
  return path;
}
