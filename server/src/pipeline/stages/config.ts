/** `config`: environment/secrets/TLS/protected-file checks against the generated app's configuration. */
import type { StageResult } from '@shared/pipeline.js';
import { runConfig } from '../../integration.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runConfigStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'config');
  const result = await runConfig(buildScanContext(ctx, 'config'));
  return absorbScanResult(ctx, 'config', started, result);
}
