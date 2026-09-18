/**
 * Feature registration, in order. Core features always mount; optional ones mount only when switched on in
 * securevibe.features.json and their code is present. Generated features are appended at the marked spot.
 */
import type { Router } from 'express';
import { config, type Features } from '../config.ts';
import { logger } from '../lib/logger.ts';
import * as account from './account/index.ts';
import * as admin from './admin/index.ts';
import * as auth from './auth/index.ts';

export interface FeatureModule {
  register(router: Router): void | Promise<void>;
}

interface OptionalFeature {
  flag: keyof Features;
  path: string;
  label: string;
}

const OPTIONAL_FEATURES: OptionalFeature[] = [
  { flag: 'uploads', path: './uploads/index.ts', label: 'File uploads' },
  { flag: 'ai', path: './ai/index.ts', label: 'AI assistant' },
  { flag: 'publicApi', path: './apikeys/index.ts', label: 'API keys' },
  { flag: 'payments', path: './payments/index.ts', label: 'Payments' },
  // Email has no routes of its own (src/features/auth/mail.ts calls src/lib/mailer.ts directly), so it is not
  // listed here. Scheduler has no user-facing routes either, but does have an admin page and a runner to start.
  { flag: 'scheduler', path: './scheduler/index.ts', label: 'Scheduled jobs' },
];

async function loadOptional(feature: OptionalFeature): Promise<FeatureModule | undefined> {
  const modulePath = new URL(feature.path, import.meta.url).href;
  try {
    const mod = (await import(modulePath)) as Partial<FeatureModule>;
    if (typeof mod.register !== 'function') {
      logger.warn({ feature: feature.flag }, `${feature.label} is switched on but its module has no register() function; skipping.`);
      return undefined;
    }
    return mod as FeatureModule;
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'ERR_MODULE_NOT_FOUND') {
      logger.warn({ feature: feature.flag, detail: (err as Error).message }, `${feature.label} is switched on in securevibe.features.json but its code is not installed; skipping.`);
      return undefined;
    }
    throw err;
  }
}

export async function registerFeatures(router: Router): Promise<string[]> {
  const mounted: string[] = [];
  auth.register(router);
  mounted.push('auth');
  account.register(router);
  mounted.push('account');
  admin.register(router);
  mounted.push('admin');

  if (config.EXAMPLE_FEATURE || config.features.example) {
    // The reference feature is removed from generated apps, so it is loaded like the other optional modules.
    const example = await loadOptional({ flag: 'example', path: './_example/index.ts', label: 'Reference notes feature' });
    if (example) {
      await example.register(router);
      mounted.push('_example');
    }
  }

  for (const feature of OPTIONAL_FEATURES) {
    if (!config.features[feature.flag]) continue;
    const mod = await loadOptional(feature);
    if (!mod) continue;
    await mod.register(router);
    mounted.push(feature.flag);
  }

  // --- generated features: SecureVibe appends registrations below this line (keep the order) ---

  logger.info({ mounted }, 'features mounted');
  return mounted;
}
