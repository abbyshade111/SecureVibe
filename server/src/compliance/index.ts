/**
 * Public entry point of the compliance module (CONTRACTS §9.4). `server/src/integration.ts` imports this
 * module dynamically under the name `evaluateCompliance`.
 */
export { evaluateCompliance } from './evaluate.js';
export { evaluateManifestControls, controlExpected, controlFailureSummary, featureEnabled } from './manifest-check.js';
export { decideStatus, contradicts, describeEvidence, notVerifiedText } from './status.js';
export type { StatusContext, StatusDecision } from './status.js';
export { evaluateSbd } from './sbd.js';
export type { EvaluateSbdInput } from './sbd.js';
export { buildTraceability } from './traceability.js';
export { buildRecommendations } from './recommendations.js';
export { summarizeStandard, computeRating } from './summaries.js';
export { buildRequirementEvidence, refMentionsRequirement, testMatchesRequirement } from './evidence.js';
export type { RequirementEvidenceCtx, RequirementEvidenceResult } from './evidence.js';
export { EvidenceIds } from './evidence-ids.js';
export type {
  AiReviewResult,
  ConfigCheckResult,
  DocsRegenerateResult,
  EvaluateInput,
  ManifestCheckContext,
  ManifestCheckOutcome,
  ManifestControlResult,
  ProbeResultLike,
  RequirementAssessment,
  RunMeta,
  TestResult,
} from './types.js';
