/**
 * Traceability matrix (CONTRACTS §9.4, DESIGN §13.12 report section 4): one row per design-time security
 * requirement (SR-xx), showing which template controls implement it and whether the build still verifies it.
 */
import type { RequirementStatus, SbdEvaluatedEntry, TraceabilityRow } from '@shared/compliance.js';
import type { DesignArtifacts } from '@shared/design.js';
import type { TemplateManifest } from '@shared/knowledge.js';

const PASSING_ISH: ReadonlySet<RequirementStatus> = new Set(['pass', 'attested', 'documented', 'ai-assessed', 'partial']);

function controlsFor(manifest: TemplateManifest, ids: string[]): string[] {
  const set = new Set<string>();
  for (const control of manifest.controls) {
    const hit = control.asvs.some((m) => ids.includes(m.id)) || control.aisvs.some((m) => ids.includes(m.id));
    if (hit) set.add(control.id);
  }
  return [...set];
}

export function buildTraceability(
  design: DesignArtifacts,
  manifest: TemplateManifest,
  requirementStatus: ReadonlyMap<string, RequirementStatus>,
  sbdEntries: SbdEvaluatedEntry[],
): TraceabilityRow[] {
  const sbdByid = new Map(sbdEntries.map((e) => [e.id, e]));
  return design.securityRequirements.map((sr) => {
    const ids = [...sr.asvs, ...sr.aisvs];
    const statuses = ids.map((id) => requirementStatus.get(id)).filter((s): s is RequirementStatus => s !== undefined);
    const sbdVerifications = sr.sbd.map((id) => sbdByid.get(id)?.verification).filter((v): v is SbdEvaluatedEntry['verification'] => v !== undefined);

    const anyFailing = statuses.includes('fail') || sbdVerifications.includes('contradicted');
    const allPass = statuses.length > 0 && statuses.every((s) => s === 'pass') && sbdVerifications.every((v) => v === 'verified');
    const anyPassish = statuses.some((s) => PASSING_ISH.has(s)) || sbdVerifications.some((v) => v === 'verified');

    let status: TraceabilityRow['status'];
    if (anyFailing) status = 'failing';
    else if (allPass && (statuses.length > 0 || sbdVerifications.length > 0)) status = 'verified';
    else if (anyPassish) status = 'partially-verified';
    else status = 'not-verified';

    return {
      requirementId: sr.id,
      statement: sr.statement,
      controls: controlsFor(manifest, ids),
      asvs: sr.asvs,
      aisvs: sr.aisvs,
      sbd: sr.sbd,
      status,
    };
  });
}
