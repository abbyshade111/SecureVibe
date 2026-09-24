/**
 * The context every stage function receives, and the small pieces the stages share (a scanner context factory,
 * the `run_checks` implementation handed to the generation/fix agents).
 */
import { join } from 'node:path';
import type { BuildSpec, DesignArtifacts } from '@shared/design.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { PipelineRun, Provenance, StageId, ToolCoverage } from '@shared/pipeline.js';
import type { Attestation, Project } from '@shared/project.js';
import type { DesignProfile } from '@shared/profile.js';
import type { SecureVibeConfig, Settings } from '../config.js';
import type { ProjectPaths, ProjectStore } from '../store/index.js';
import type { AiReviewResult, ComplianceTestResult, DastAuthBootstrap, Frameworks, Knowledge, LlmProvider, LlmPurpose, ProbeResult, ScanContext } from '../integration.js';
import type { RunBus } from './bus.js';

/** Findings/evidence/coverage a stage adds are appended here; nothing is discarded between stages. */
export interface PipelineAccumulator {
  findings: Finding[];
  evidence: Evidence[];
  coverage: ToolCoverage[];
  testResults: ComplianceTestResult[];
  probeResults: ProbeResult[];
  correlationIds: string[];
  servedModels: string[];
}

export interface PipelineCtx {
  store: ProjectStore;
  config: SecureVibeConfig;
  settings: Settings;
  project: Project;
  run: PipelineRun;
  paths: ProjectPaths;
  appDir: string;
  knowledge: Knowledge;
  frameworks: Frameworks;
  /** The provider for the default service; `providerFor(purpose)` is what each AI step should use. */
  provider: LlmProvider;
  /** The provider for one step, which may be a different AI service (Settings → "Which AI service does what"). */
  providerFor: (purpose: LlmPurpose) => LlmProvider;
  bus: RunBus;
  abort: AbortController;
  acc: PipelineAccumulator;

  /** Set once design-freeze has run (verify-only mode reads it back from project.design/project.profile). */
  design?: DesignArtifacts;
  /** The validated (non-partial) profile the frozen design was derived from. */
  profile?: DesignProfile;
  buildSpec?: BuildSpec;
  manifest?: TemplateManifest;
  provenance?: Provenance;
  featureFlags?: Record<string, boolean>;
  aiReviewResult?: AiReviewResult;

  fixFindingIds: string[];
  approvedBy?: string;
  spendingCapUsd: number;

  /** Self-assessment/verify CLI: a custom sign-in bootstrap for `dast` (SecureVibe has no sign-in form of its own). */
  dastAuth?: DastAuthBootstrap;
  /** Extra scanner ignore patterns on top of the built-in ones (self-assessment excludes workspace/, artifacts/, …). */
  extraIgnore?: string[];
  /**
   * Self-assessment: results of SecureVibe's own test suite (vitest), run by the CLI just before the pipeline.
   * The generated-app test runner does not apply to SecureVibe, so these replace it.
   */
  importedTests?: { tool: string; results: import('../compliance/types.js').TestResult[] };
  /** Self-assessment: start SecureVibe in-process, its route list, and the probes that do not apply to it. */
  dastExtra?: Pick<import('../scanners/dast/index.js').DastOptions, 'start' | 'routes' | 'notApplicable'>;
  /** Requirement ids the AI review leaves out (already verified by automated checks), to save cost. */
  aiReviewSkip?: Set<string>;
  /** Self-assessment: reviewed rule-level decisions (see scanners/normalize.ts). */
  ruleDecisions?: import('../scanners/normalize.js').RuleDecision[];
  /** The feature plan the owner approved for this build (full builds with AI); the agent's to-do list. */
  plan?: import('@shared/project.js').BuildPlan;
  /** Checks whose results are left out of this run (see RunPipelineOptions.excludedChecks). */
  excludedChecks?: Set<string>;
  /** Why, in the words the stage summary uses: "only apply to apps built by SecureVibe" for an uploaded app. */
  excludedChecksReason?: string;

  log(stage: StageId, message: string): void;
}

export function attestationsOf(ctx: PipelineCtx): Attestation[] {
  return ctx.project.attestations;
}

/** Builds the ScanContext every static/runtime scanner takes, from the pipeline context. */
export function buildScanContext(ctx: PipelineCtx, stage: StageId, extraIgnore: string[] = []): ScanContext {
  if (!ctx.buildSpec || !ctx.manifest) throw new Error('buildScanContext called before scaffold');
  return {
    appDir: ctx.appDir,
    projectDir: ctx.paths.dir,
    runId: ctx.run.id,
    buildSpec: ctx.buildSpec,
    manifest: ctx.manifest,
    ...(ctx.provenance ? { provenance: ctx.provenance } : {}),
    ignore: [...(ctx.extraIgnore ?? []), ...extraIgnore],
    toolCacheDir: join(ctx.config.paths.home, 'cache', 'tools'),
    knowledge: ctx.knowledge,
    log: (msg: string) => ctx.log(stage, msg),
    abort: ctx.abort.signal,
  };
}
