/**
 * The internal, fully-populated model every section renderer in this module works from. `reports/index.ts` is
 * the only place that adapts the public contract (`../reports-contract.ts`, owned by the integration module) —
 * which leaves `compliance`, `provenance` and several other fields optional — into this required shape, filling
 * safe fallbacks when the pipeline could not supply them (an incomplete run, a preview build, no SBOM yet).
 */
import type { ComplianceResult } from '@shared/compliance.js';
import type { DesignArtifacts } from '@shared/design.js';
import type { Finding } from '@shared/findings.js';
import type { PipelineRun, Provenance, ToolCoverage } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import type { Project } from '@shared/project.js';
import type { Knowledge } from '../frameworks/index.js';
import type { ProbeResultLike, TestResult } from '../compliance/types.js';

export interface ReportModel {
  project: Project;
  design: DesignArtifacts;
  /** The full design profile; derived from `project.profile` by `reports/index.ts` when it validates. */
  profile?: DesignProfile;
  run: PipelineRun;
  compliance: ComplianceResult;
  findings: Finding[];
  coverage: ToolCoverage[];
  probeResults: ProbeResultLike[];
  testResults: TestResult[];
  /** Path to the CycloneDX SBOM file, relative to `appDir`, when one could be found for this run. */
  sbomPath?: string;
  provenance: Provenance;
  knowledge: Knowledge;
  appDir: string;
  outDir: string;
  securevibeVersion: string;
  /** design.md content when the design engine already rendered it; rendered here from `design`+`profile` otherwise. */
  designMarkdown?: string;
  /** Findings of the previous run, for the "delta vs previous" summary line. */
  previousFindings?: Finding[];
}
