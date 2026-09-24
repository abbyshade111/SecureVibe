import { createHash } from 'node:crypto';
import type { DesignProfile } from '@shared/profile.js';

/** JSON with object keys sorted recursively so equal values always serialize identically. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * sha256 of the canonical JSON of the decision-relevant profile sections (app, users, data, capabilities,
 * deployment). `meta` is bookkeeping (confirmation flags, inferred-field lists) and does not change the design,
 * so it is left out: flipping `meta.confirmed` must not mark a design as stale.
 */
export function profileHash(profile: DesignProfile): string {
  // `app.theme` is left out because it decides nothing. The colors are picked from a fixed set, every one of
  // them contrast-tested in both light and dark, and the page offering them promises the change costs nothing and
  // cannot affect how the app protects data. Including it in the hash made that promise false: choosing a color
  // voided the approved build plan and every AI verdict a rebuild could have carried forward, and an owner who
  // then asked the AI to fix a finding was refused with "approve the build plan first" — for changing a color.
  const { theme: _theme, ...app } = profile.app;
  const { users, data, capabilities, deployment } = profile;
  return sha256Hex(canonicalJson({ app, users, data, capabilities, deployment }));
}
