import { createHash } from 'node:crypto';
import type { DesignProfile } from '@shared/profile.js';

/** JSON with object keys sorted recursively so equal values always serialise identically. */
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
  const { app, users, data, capabilities, deployment } = profile;
  return sha256Hex(canonicalJson({ app, users, data, capabilities, deployment }));
}
