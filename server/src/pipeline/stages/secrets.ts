/** `secrets`: regex/entropy secret scanning over the generated app. */
import type { StageResult } from '@shared/pipeline.js';
import { runSecrets } from '../../integration.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runSecretsStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'secrets');
  const result = await runSecrets(buildScanContext(ctx, 'secrets'));
  return absorbScanResult(ctx, 'secrets', started, result);
}
