/** `unit-tests`: runs the generated app's own security + feature test suite. Skipped when `install` did not succeed. */
import type { StageResult } from '@shared/pipeline.js';
import { runTests } from '../../integration.js';
import { absorbScanResult, finishStage, installFailed, skipStage, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runUnitTestsStage(ctx: PipelineCtx): Promise<StageResult> {
  if (installFailed(ctx)) {
    return skipStage(ctx, 'unit-tests', 'The packages did not install, so the tests could not run.');
  }
  const started = startStage(ctx, 'unit-tests');
  if (ctx.importedTests) return importedTestsStage(ctx, started, ctx.importedTests);
  const result = await runTests(buildScanContext(ctx, 'unit-tests'));
  const stage = absorbScanResult(ctx, 'unit-tests', started, result);
  const details = result.details as { total?: number; passed?: number; failed?: number; tests?: unknown } | undefined;
  if (details) ctx.acc.testResults.push(...((details.tests as PipelineCtx['acc']['testResults']) ?? []));
  return stage;
}

function importedTestsStage(ctx: PipelineCtx, started: Date, imported: NonNullable<PipelineCtx['importedTests']>): StageResult {
  const results = imported.results;
  const ran = results.filter((t) => !t.skipped);
  const failed = ran.filter((t) => !t.ok);
  ctx.acc.testResults.push(...results);
  ctx.acc.coverage.push({ tool: 'tests', ran: true, version: imported.tool, covers: `SecureVibe's own automated test suite (${imported.tool}), run just before this assessment.` });
  const summary = `Ran ${results.length} tests from ${imported.tool}: ${ran.length - failed.length} passed, ${failed.length} failed, ${results.length - ran.length} skipped.`;
  return finishStage(ctx, 'unit-tests', failed.length > 0 ? 'failed' : results.length === 0 ? 'skipped' : 'passed', summary, started, {
    details: { total: results.length, passed: ran.length - failed.length, failed: failed.length, tool: imported.tool, failures: failed.slice(0, 50).map((t) => t.name) },
  });
}
