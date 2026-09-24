/**
 * Pre-build cost/time estimate (CONTRACTS §9.5) shown before the person approves a build, and the DASHBOARD used
 * by `GET /api/projects/:id/estimate`. Wraps `llm/budget.ts`'s `estimateCost` with SecureVibe's current settings.
 */
import type { BuildSpec } from '@shared/design.js';
import type { CostEstimate } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import { effectiveAiSettings, type Settings } from '../config.js';
import { estimateCost } from '../integration.js';

export function estimateForProject(profile: DesignProfile, buildSpec: BuildSpec, raw: Settings, opts: { reviewOnly?: boolean } = {}): CostEstimate {
  // Writing the app is the expensive step, so the estimate is priced at that step's service and model.
  const settings = effectiveAiSettings(raw, opts.reviewOnly ? 'ai-review' : 'generate');
  return estimateCost(profile, buildSpec, {
    model: settings.model,
    generationEffort: settings.generationEffort,
    reviewEffort: settings.reviewEffort,
    defaultSpendingCapUsd: settings.defaultSpendingCapUsd,
    maxFixRounds: settings.maxFixRounds,
    ...(opts.reviewOnly ? { reviewOnly: true } : {}),
  });
}

/**
 * The AI review of an app whose questions have not been answered: reviewed against ASVS Level 1 with no records
 * and no features known, which is what the estimate's own formula prices as the smallest review. Typed loosely
 * on purpose: only the counts are read (see llm/budget.ts estimateCost).
 */
export function estimateReviewWithoutAnswers(raw: Settings): CostEstimate {
  const settings = effectiveAiSettings(raw, 'ai-review');
  const emptyProfile = { app: { entities: [] } } as unknown as DesignProfile;
  const emptySpec = { features: {} } as unknown as BuildSpec;
  return estimateCost(emptyProfile, emptySpec, {
    model: settings.model,
    generationEffort: settings.generationEffort,
    reviewEffort: settings.reviewEffort,
    defaultSpendingCapUsd: settings.defaultSpendingCapUsd,
    maxFixRounds: settings.maxFixRounds,
    reviewOnly: true,
  });
}
