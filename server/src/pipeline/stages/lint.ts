/** `lint`: eslint-plugin-security over the generated app, using SecureVibe's own ESLint install. */
import type { StageResult } from '@shared/pipeline.js';
import { runLint } from '../../integration.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runLintStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'lint');
  const result = await runLint(buildScanContext(ctx, 'lint'));
  return absorbScanResult(ctx, 'lint', started, result);
}
