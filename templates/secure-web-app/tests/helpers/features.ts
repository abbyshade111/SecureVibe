/**
 * Reads `securevibe.features.json` (written by the SecureVibe scaffolder next to package.json) so tests for
 * optional features can skip cleanly when a feature is off. Accepts either the BuildSpec `features` object
 * (camelCase keys, optionally nested under "features") or the manifest feature ids (kebab-case).
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const templateRoot = join(import.meta.dirname, '..', '..');
export const featuresFile = join(templateRoot, 'securevibe.features.json');

export type FeatureId =
  | 'auth'
  | 'admin-mfa'
  | 'user-mfa'
  | 'uploads'
  | 'ai'
  | 'ai-actions'
  | 'ai-moderation'
  | 'ai-history'
  | 'email'
  | 'scheduler'
  | 'public-api'
  | 'payments'
  | 'field-encryption'
  | 'retention'
  | 'external-apis'
  | 'example';

const aliases: Record<FeatureId, string[]> = {
  auth: ['auth'],
  'admin-mfa': ['admin-mfa', 'adminMfa'],
  'user-mfa': ['user-mfa', 'userMfa'],
  uploads: ['uploads', 'fileUploads'],
  ai: ['ai', 'aiAssistant'],
  'ai-actions': ['ai-actions', 'aiActions'],
  'ai-moderation': ['ai-moderation', 'aiModeration'],
  'ai-history': ['ai-history', 'aiHistory', 'storesHistory'],
  email: ['email'],
  scheduler: ['scheduler', 'scheduledJobs'],
  'public-api': ['public-api', 'publicApi'],
  payments: ['payments'],
  'field-encryption': ['field-encryption', 'fieldEncryption'],
  retention: ['retention', 'retentionJobs'],
  'external-apis': ['external-apis', 'externalApis'],
  example: ['example', 'exampleFeature'],
};

/** Features that are always part of the template regardless of the features file. */
const alwaysOn = new Set<FeatureId>(['auth', 'admin-mfa', 'user-mfa', 'field-encryption']);

let cache: Record<string, unknown> | null | undefined;

function load(): Record<string, unknown> | null {
  if (cache !== undefined) return cache;
  if (!existsSync(featuresFile)) {
    cache = null;
    return cache;
  }
  const parsed = JSON.parse(readFileSync(featuresFile, 'utf8')) as Record<string, unknown>;
  const nested = parsed.features;
  cache = nested && typeof nested === 'object' ? { ...parsed, ...(nested as Record<string, unknown>) } : parsed;
  return cache;
}

export function hasFeaturesFile(): boolean {
  return load() !== null;
}

/**
 * `true`/`false` when the features file states it; `undefined` when there is no features file
 * (callers may then fall back to route discovery).
 */
export function featureFromFile(id: FeatureId): boolean | undefined {
  const data = load();
  if (data === null) return alwaysOn.has(id) ? true : undefined;
  for (const key of aliases[id]) {
    const v = data[key];
    if (typeof v === 'boolean') return v;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'string') return v !== '' && v !== 'off' && v !== '0';
  }
  const list = data.enabled ?? data.list;
  if (Array.isArray(list)) return list.some((x) => aliases[id].includes(String(x)));
  return alwaysOn.has(id);
}

export function skipReason(id: FeatureId): string {
  return `feature "${id}" is not enabled in securevibe.features.json`;
}
