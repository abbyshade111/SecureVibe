/** `sast`: the TypeScript-AST rule engine over the generated app's source. */
import type { StageResult } from '@shared/pipeline.js';
import { runSast } from '../../integration.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runSastStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'sast');
  const result = await runSast(buildScanContext(ctx, 'sast'));
  return absorbScanResult(ctx, 'sast', started, result);
}
