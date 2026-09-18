/**
 * The fix stage: Claude repairs the findings the checks reported, under the same tools, contract and budgets as the
 * generation stage.
 *
 * This flow only *attempts* fixes. Whether a finding counts as fixed is decided later by the pipeline, by re-running
 * the detector that found it (DESIGN §13 item 11) — never by asking the model whether it succeeded.
 */
import type { Finding } from '@shared/findings.js';
import { emptyLlmUsage } from '../budget.js';
import { renderFinding } from './context.js';
import { runAgentTask, type AgentFlowOutcome, type AgentTaskInput } from './generate.js';
import type { LlmProvider } from '../types.js';

export interface FixInput extends AgentTaskInput {
  findings: Finding[];
  /** Which fix round this is (1-based); shown to the model so it knows a previous attempt did not work. */
  round?: number;
}

export interface FixAttempt {
  findingId: string;
  /** True when the agent finished and its work plausibly covers this finding (it named it, or touched its file). */
  attempted: boolean;
  /** Files the tools changed that relate to this finding. */
  filesTouched: string[];
}

export interface FixOutcome extends AgentFlowOutcome {
  attempts: FixAttempt[];
}

export async function fixFindings(provider: LlmProvider, input: FixInput): Promise<FixOutcome> {
  if (input.findings.length === 0) {
    return {
      ok: true,
      status: 'done',
      message: 'There was nothing to fix.',
      summary: 'No findings were sent to the repair step.',
      routesManifest: [],
      filesTouched: [],
      claimedFiles: [],
      usage: emptyLlmUsage(provider.name, provider.model),
      iterations: 0,
      servedModels: [],
      pathDenials: 0,
      injectionFlags: 0,
      attempts: [],
    };
  }

  const user = [
    input.round && input.round > 1
      ? `This is repair round ${input.round}. An earlier attempt did not remove these problems, so look again rather than repeating the same change.`
      : 'These are the problems the security checks found in the application.',
    '',
    'FINDINGS',
    ...input.findings.map((f, i) => renderFinding(f, i + 1)),
    '',
    'Fix each one at its cause. If one of them is not a real problem, leave the code alone and say why in the summary.',
    'Do not change any protected file, do not delete or weaken a test, and do not add a dependency.',
  ].join('\n');

  const outcome = await runAgentTask(provider, 'fix', user, input, 'fix');
  return { ...outcome, attempts: attributeAttempts(input.findings, outcome) };
}

/**
 * Attributes the agent's work to the findings it was given: a finding counts as attempted when the run finished and
 * the summary names it, or a file it points at was changed. Nothing here decides that a finding is fixed.
 */
export function attributeAttempts(findings: Finding[], outcome: AgentFlowOutcome): FixAttempt[] {
  const touched = new Set(outcome.filesTouched);
  const summary = outcome.summary.toLowerCase();
  return findings.map((f) => {
    const file = f.location?.file;
    const relatedFiles = file && touched.has(file) ? [file] : [];
    const named = summary.includes(f.id.toLowerCase()) || summary.includes(f.ruleId.toLowerCase());
    return {
      findingId: f.id,
      attempted: outcome.ok && (named || relatedFiles.length > 0),
      filesTouched: relatedFiles,
    };
  });
}
