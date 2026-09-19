/**
 * One way of saying what a run's findings are *now*.
 *
 * A run record holds what the checks found when they ran. What is still open depends on what a person has decided
 * since — accepted as it stands, or judged never to have been a real problem — and those decisions live on the
 * project, matched by fingerprint so they survive a rebuild. Both the per-app findings route and the across-apps
 * view need the same answer, and two copies of this would be two ideas of what "open" means.
 */
import type { Finding } from '@shared/findings.js';
import type { PipelineRun } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';

export function withDecisions(run: PipelineRun, project: Project): Finding[] {
  return run.findings.map((f) => {
    const decision = project.findingDecisions.find((d) => d.fingerprint === f.fingerprint);
    return decision ? { ...f, status: decision.status, triage: decision.triage } : f;
  });
}
