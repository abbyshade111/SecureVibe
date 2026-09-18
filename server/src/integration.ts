/**
 * Central import point for the modules other agents own (frameworks, design, llm, scanners, compliance, reports).
 *
 * Everything the pipeline, the generator and the API routes need from another module comes through here, so an
 * integration mismatch — a renamed export, a changed function signature — is a one-file fix instead of a
 * search-and-replace across this module.
 *
 * `compliance/index.ts` and `reports/**` are owned by other agents and did not exist on disk when this file was
 * written. They are loaded through `evaluateCompliance`/`renderReports` at the bottom of this file with a
 * *dynamic* import — a plain `export ... from './reports/index.js'` would make Node fail to resolve this whole
 * module (and therefore the whole server) the instant anything imports it, since static ESM imports are resolved
 * eagerly before any code runs. The dynamic form resolves lazily, the first time it is actually called, and
 * degrades to a clear "not available yet" result instead of a crash. Once those two files exist and export a
 * function under these names, both wrappers start returning real results with no other code changes needed.
 */
import type { ComplianceResult } from '@shared/compliance.js';
import type { EvaluateInput } from './compliance/types.js';
import type { RenderReportsInput, RenderReportsResult } from './reports-contract.js';

// --- frameworks --------------------------------------------------------------------------------------------------
export { computeApplicability, loadFrameworks, loadKnowledge } from './frameworks/index.js';
export type { ApplicabilityOptions, ConditionContext } from './frameworks/index.js';
export type { Frameworks, Knowledge, WizardCopy } from './frameworks/index.js';

// --- design (SbD engine) ------------------------------------------------------------------------------------------
export { buildSpecFor, canonicalJson, deriveDesign, profileHash, renderDesignMarkdown, sha256Hex, whatThisChanges } from './design/index.js';
export type { DeriveDesignDeps, RenderedDesign } from './design/index.js';

// --- llm -------------------------------------------------------------------------------------------------------
export {
  aiReview,
  appendAudit,
  applyPeerReviewPatch,
  createProvider,
  estimateCost,
  fixFindings,
  generateApp,
  hasCredentials,
  loadDefaultInjectionPatterns,
  peerReview,
  promptLibraryHash,
  providerStatus,
  quickInfer,
  screenText,
  threatModel,
} from './llm/index.js';
export type { LlmProvider, ProviderStatus } from './llm/index.js';
export { generateApp as generateAppFlow, runAgentTask, failureOptions } from './llm/flows/generate.js';
export { attributeAttempts } from './llm/flows/fix.js';
export { createAgentTools, DoneInputSchema } from './llm/tools.js';
export type { RouteManifestEntry, RunCheckOutcome, CheckName } from './llm/tools.js';
export { toAiReviewResult, buildSentFiles } from './llm/flows/ai-review.js';
export type { ReviewFile, RequirementBatch, RequirementForReview } from './llm/flows/ai-review.js';
export { emptyLlmUsage, addUsage, mergeUsage, DEFAULT_BUDGETS } from './llm/budget.js';

// --- scanners --------------------------------------------------------------------------------------------------
export { runAstCheck, runConfig, runLint, runSast, runSecrets } from './scanners/index-static.js';
export { runDast, runDeps, runExternal, runTests, formAuthBootstrap, startupTokenAuthBootstrap, detectTool, EXTERNAL_TOOLS } from './scanners/index-runtime.js';
export type { DastAuthBootstrap, ProbeResult } from './scanners/index-runtime.js';
export { finalizeFindings } from './scanners/normalize.js';
export type { ScanContext, ScanResult, Scanner } from './scanners/types.js';

// --- compliance ------------------------------------------------------------------------------------------------
// evaluateManifestControls exists today (server/src/compliance/manifest-check.ts); evaluateCompliance (the
// CONTRACTS §9.4 `evaluate` function) does not exist yet — see `evaluateCompliance` below.
export { evaluateManifestControls } from './compliance/manifest-check.js';
export type { AiReviewResult, EvaluateInput, ManifestCheckContext, ManifestControlResult, RunMeta, TestResult as ComplianceTestResult } from './compliance/types.js';

export type { RenderReportsInput, RenderReportsResult } from './reports-contract.js';

let compliancePromise: Promise<{ evaluateCompliance?: (input: EvaluateInput) => ComplianceResult } | undefined> | undefined;
function loadComplianceModule() {
  if (!compliancePromise) {
    compliancePromise = (
      import('./compliance/index.js') as Promise<{ evaluateCompliance?: (input: EvaluateInput) => ComplianceResult }>
    ).catch(() => undefined);
  }
  return compliancePromise;
}

/** CONTRACTS §9.4's `evaluate`, resolved lazily. `ok: false` (with a plain-language reason) until compliance/index.ts exists. */
export async function evaluateCompliance(input: EvaluateInput): Promise<{ ok: true; result: ComplianceResult } | { ok: false; reason: string }> {
  const mod = await loadComplianceModule();
  if (!mod?.evaluateCompliance) return { ok: false, reason: 'The compliance engine (compliance/index.ts) is not available in this build of SecureVibe yet.' };
  return { ok: true, result: mod.evaluateCompliance(input) };
}

let reportsPromise: Promise<{ renderReports?: (input: RenderReportsInput) => Promise<RenderReportsResult> | RenderReportsResult } | undefined> | undefined;
function loadReportsModule() {
  if (!reportsPromise) {
    reportsPromise = (
      import('./reports/index.js') as Promise<{ renderReports?: (input: RenderReportsInput) => Promise<RenderReportsResult> | RenderReportsResult }>
    ).catch(() => undefined);
  }
  return reportsPromise;
}

/** Renders the compliance/security/overview reports, resolved lazily. `ok: false` until reports/index.ts exists. */
export async function renderReports(input: RenderReportsInput): Promise<{ ok: true; result: RenderReportsResult } | { ok: false; reason: string }> {
  const mod = await loadReportsModule();
  if (!mod?.renderReports) return { ok: false, reason: 'The report renderer (reports/index.ts) is not available in this build of SecureVibe yet.' };
  return { ok: true, result: await mod.renderReports(input) };
}
