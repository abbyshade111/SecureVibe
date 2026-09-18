/** run-log.txt: a plain-text, chronological record of every pipeline stage for this run. */
import type { PipelineRun } from '@shared/pipeline.js';

export function renderRunLog(run: PipelineRun): string {
  const lines: string[] = [`SecureVibe run ${run.id} — mode: ${run.mode} — status: ${run.status}`, `Started: ${run.startedAt}`, `Finished: ${run.finishedAt ?? '(not finished)'}`, ''];
  for (const s of run.stages) {
    const duration = s.durationMs !== undefined ? `${s.durationMs}ms` : '';
    lines.push(`[${s.status.toUpperCase().padEnd(8)}] ${s.id.padEnd(14)} ${duration.padStart(8)}  ${s.summary}${s.skippedReason ? ` (skipped: ${s.skippedReason})` : ''}`);
  }
  if (run.failure) {
    lines.push('', `FAILURE: ${run.failure.message}`);
    if (run.failure.detail) lines.push(run.failure.detail);
  }
  if (run.incomplete) lines.push('', 'This run is marked incomplete: reports were rendered from partial results.');
  // A continued build wrote part of this app in an earlier run; the report says so rather than implying one sitting.
  if (run.resumedFrom) lines.push('', `Continued from run ${run.resumedFrom}. ${run.resumedNote ?? ''}`.trimEnd());
  return lines.join('\n') + '\n';
}
