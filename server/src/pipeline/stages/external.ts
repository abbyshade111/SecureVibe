/** `external`: semgrep / gitleaks / trivy / osv-scanner, when installed on this computer. */
import type { StageResult } from '@shared/pipeline.js';
import { runExternal } from '../../integration.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runExternalStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'external');
  const result = await runExternal(buildScanContext(ctx, 'external'));
  return absorbScanResult(ctx, 'external', started, result);
}
