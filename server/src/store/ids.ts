/**
 * Identifiers: project ids are "p_" + 10 base32 characters, run ids "r_" + a sortable timestamp + 6 base32
 * characters, so a folder listing reads in chronological order.
 */
import { randomBytes } from 'node:crypto';

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

export function randomBase32(length: number): string {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += BASE32[(bytes[i] as number) % 32];
  return out;
}

export function newProjectId(): string {
  return `p_${randomBase32(10)}`;
}

export const PROJECT_ID_PATTERN = /^p_[a-z2-7]{10}$/;

export function isProjectId(value: string): boolean {
  return PROJECT_ID_PATTERN.test(value);
}

export function newRunId(now: Date = new Date()): string {
  const stamp = now.toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  return `r_${stamp}_${randomBase32(6)}`;
}

export const RUN_ID_PATTERN = /^r_\d{14}_[a-z2-7]{6}$/;

export function isRunId(value: string): boolean {
  return RUN_ID_PATTERN.test(value);
}

export function newAttestationId(): string {
  return `att_${randomBase32(8)}`;
}

export function newCorrelationId(): string {
  return `c_${randomBase32(12)}`;
}
