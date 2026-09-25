/**
 * The shape `reports/index.ts` (owned by another agent, not yet written) is expected to implement, per
 * DESIGN.md §9 and CONTRACTS.md §9.6/§12: `renderReports(input): Promise<RenderReportsResult> | RenderReportsResult`.
 *
 * Kept as its own file (rather than inline in integration.ts) so the reports module can import these types
 * directly instead of guessing at them.
 */
import type { ComplianceResult } from '@shared/compliance.js';
import type { DesignArtifacts } from '@shared/design.js';
import type { Finding } from '@shared/findings.js';
import type { ArtifactRef, LlmUsage, PipelineRun, Provenance, StageResult, ToolCoverage } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import type { Frameworks, Knowledge } from './frameworks/index.js';

export interface RenderReportsInput {
  project: Project;
  run: PipelineRun;
  design: DesignArtifacts;
  manifest?: TemplateManifest;
  provenance?: Provenance;
  findings: Finding[];
  compliance?: ComplianceResult;
  coverage: ToolCoverage[];
  llmUsage?: LlmUsage;
  stages: StageResult[];
  /** Absolute path to write the rendered reports and their embedded downloads into (`reports/<runId>/`). */
  outDir: string;
  /** Absolute path of the generated application, for a source zip and for re-reading any file the report cites. */
  appDir?: string;
  knowledge: Knowledge;
  frameworks: Frameworks;
  securevibeVersion: string;
  /** Paper size of the PDF copies; US Letter when left out. */
  pdfPageSize?: 'letter' | 'a4';
}

export interface RenderReportsResult {
  /** Every file written to `outDir`, ready to become `PipelineRun.artifacts`. */
  artifacts: ArtifactRef[];
}
