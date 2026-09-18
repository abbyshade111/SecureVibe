/**
 * Inputs of the compliance engine (CONTRACTS §9.4) that are not shared types: what the test runner, the runtime
 * scanner, the AI review and the pipeline hand over, and the per-control result of the manifest check.
 *
 * Other modules own the producers of these values; the shapes here are the minimum this module reads so the
 * pipeline can pass its richer objects unchanged (ProbeResult from scanners/dast is assignable to ProbeResultLike).
 */
import type { ComplianceResult, Evidence } from '@shared/compliance.js';
import type { BuildSpec, DesignArtifacts } from '@shared/design.js';
import type { Confidence, Finding } from '@shared/findings.js';
import type { ManifestCheck, TemplateManifest } from '@shared/knowledge.js';
import type { Provenance, RunMode, StageResult, ToolCoverage } from '@shared/pipeline.js';
import type { Attestation, HumanCodeReview } from '@shared/project.js';
import type { Audience, DeploymentTarget, DesignProfile } from '@shared/profile.js';
import type { Frameworks, Knowledge } from '../frameworks/index.js';
import type { ProbeResult } from '../scanners/dast/types.js';
import type { AstCheckResult } from '../scanners/types.js';

/** One test of the generated app as parsed from the TAP output (CONTRACTS §1.13). */
export interface TestResult {
  /** Full test name; it contains the requirement id it evidences ("V6.2.1 rejects short passwords"). */
  name: string;
  ok: boolean;
  file?: string;
  skipped?: boolean;
  durationMs?: number;
  detail?: string;
}

/** A runtime probe outcome; `passed: null` means the probe could not run (never counts as evidence). */
export type ProbeResultLike = Pick<ProbeResult, 'id' | 'passed'> &
  Partial<
    Pick<
      ProbeResult,
      'reason' | 'expected' | 'observed' | 'requirementIds' | 'endpoint' | 'group' | 'phase' | 'requestExcerpt' | 'responseExcerpt' | 'durationMs'
    >
  >;

/** A config check outcome (`config.*` / `deps.*` ids from CONTRACTS §4). */
export interface ConfigCheckResult {
  id: string;
  passed: boolean | null;
  detail: string;
}

export interface DocsRegenerateResult {
  matches: boolean;
  detail?: string;
}

export interface ManifestCheckContext {
  appDir: string;
  buildSpec: BuildSpec;
  testResults: TestResult[];
  probeResults: ProbeResultLike[];
  astCheck(name: string, file?: string): AstCheckResult | Promise<AstCheckResult>;
  configResults: ConfigCheckResult[];
  /** Findings from the static scanners (open ones fail `sast-clean` checks). */
  sastFindings: Finding[];
  docsRegenerate(file: string): DocsRegenerateResult | Promise<DocsRegenerateResult>;
  /** Feature flags the manifest may name that BuildSpec does not carry (e.g. "ai-history", "external-apis"). */
  extraFeatures?: Record<string, boolean>;
  /** Stages that did not run, with the plain-language reason: their checks are skipped, not failed. */
  skipped?: { tests?: string; dast?: string; sast?: string; config?: string; docs?: string };
  runId?: string;
  capturedAt?: string;
}

export interface ManifestCheckOutcome {
  check: ManifestCheck;
  passed: boolean;
  detail: string;
  /** Set when the check could not run (its stage was skipped); such a check never passes. */
  skippedReason?: string;
  /** Set when running the check threw. */
  errored?: boolean;
}

export interface ManifestControlResult {
  controlId: string;
  /** False when the control is not expected in this build (feature off, TLS mode); no checks are run then. */
  expected: boolean;
  notExpectedReason?: string;
  checks: ManifestCheckOutcome[];
  /** Credited: every check passed and at least one test/dast/ast/config-value/doc-generated check passed. */
  passed: boolean;
  creditedBy: ManifestCheck['type'][];
  /** True when the only crediting checks were doc-generated: the control is documented rather than proven. */
  docOnly: boolean;
  skippedReason?: string;
  errored: boolean;
  evidence: Evidence[];
}

export interface AiReviewCitation {
  file: string;
  line?: number;
  snippet?: string;
  /** The verbatim snippet was found at the cited location on the file tree sent to the model. */
  verified: boolean;
}

export interface RequirementAssessment {
  requirementId: string;
  status: 'pass' | 'partial' | 'fail' | 'not-applicable' | 'unknown';
  confidence: Confidence;
  rationale: string;
  citations: AiReviewCitation[];
}

export interface AiReviewResult {
  performed: boolean;
  model?: string;
  promptHash?: string;
  assessments: RequirementAssessment[];
  /** Requirement ids the model was asked about (its coverage), when known. */
  reviewedRequirementIds?: string[];
  declined?: boolean;
  declinedReason?: string;
  skippedReason?: string;
  /** Citations that did not match the cited location (hallucination metric). */
  unverifiedCitations?: number;
}

/** Facts about the pipeline run the evaluation needs (AISVS Appendix C evidence, not-verified reasons, gating). */
export interface RunMeta {
  runId: string;
  previousRunId?: string;
  mode: RunMode;
  /** LLM provider that served this run; `null` or 'null' = preview mode (no AI generation, no AI review). */
  provider: 'anthropic' | 'scripted' | 'null' | null;
  model?: string;
  generatedAt?: string;
  appDir?: string;
  stages?: StageResult[];
  coverage?: ToolCoverage[];
  provenance?: Provenance;
  approvedAt?: string;
  approvedBy?: string;
  /** SecureVibe's LLM audit log (llm-audit.jsonl) has entries for this run. */
  auditLogPresent?: boolean;
  /** Untrusted text (wizard free text, file contents sent for review) was screened for injection patterns. */
  screeningPerformed?: boolean;
  screeningEvents?: number;
  /** Protected template files hash-verified against the scaffold-time hashes (undefined = not checked). */
  protectedHashesVerified?: boolean;
  escalationAcknowledgedAt?: string;
  sandbox?: { mode: string; note: string };
  incomplete?: boolean;
  fixRounds?: number;
  appName?: string;
  ownerName?: string;
  deploymentTarget?: DeploymentTarget;
  audience?: Audience;
}

export interface EvaluateInput {
  design: DesignArtifacts;
  /** The full design profile when available (deployment target, audience, app name); derived from the design otherwise. */
  profile?: DesignProfile;
  manifest: TemplateManifest;
  manifestResults: ManifestControlResult[];
  findings: Finding[];
  /** Extra evidence produced by scanners; attached to the requirement ids found in `ref` (e.g. "config:V13.2.3"). */
  evidence: Evidence[];
  testResults: TestResult[];
  probeResults: ProbeResultLike[];
  aiReview?: AiReviewResult;
  attestations: Attestation[];
  humanReview?: HumanCodeReview;
  runMeta: RunMeta;
  previous?: ComplianceResult;
  /** Findings of the previous run (for the new/fixed counts in changesSincePrevious). */
  previousFindings?: Finding[];
  knowledge: Knowledge;
  frameworks?: Frameworks;
}
