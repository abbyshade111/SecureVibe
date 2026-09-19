/**
 * Compliance evaluation results (SbD checklist, ASVS, AISVS, AISVS Appendix C) and the evidence model.
 *
 * Honesty rules (enforced by server/src/compliance and asserted by tests):
 *  - `pass` requires >= 1 passing STRONG evidence item, or >= 2 passing MEDIUM items, and no failing evidence.
 *  - Evidence from the AI review alone can only produce `ai-assessed` (never `pass`).
 *  - Generated documentation alone can only produce `documented`.
 *  - A human attestation alone produces `attested`.
 *  - Requirements in the `manual-only` class can never be `pass`.
 */
import { z } from 'zod';
import { SbdChecklistEntrySchema } from './design.js';

export const EvidenceTypeSchema = z.enum([
  'template-control', // a manifest control whose checks all passed on the generated code (medium)
  'test', // a named automated test passed/failed in the generated app (strong)
  'dast', // a runtime probe passed/failed against the running app (strong)
  'scanner', // static/dependency/config scanner result: finding present (fail) or "no issues detected" (medium)
  'config', // a config-value check (medium)
  'ai-review', // an assessment by Claude with a verified verbatim citation (weak)
  'design', // a recorded design decision / generated document (weak)
  'manual', // supplied by a human (attestation, imported review) with a note (weak)
]);
export type EvidenceType = z.infer<typeof EvidenceTypeSchema>;

export const EvidenceTierSchema = z.enum(['strong', 'medium', 'weak']);
export type EvidenceTier = z.infer<typeof EvidenceTierSchema>;

export const EVIDENCE_TIER: Record<EvidenceType, EvidenceTier> = {
  test: 'strong',
  dast: 'strong',
  'template-control': 'medium',
  scanner: 'medium',
  config: 'medium',
  'ai-review': 'weak',
  design: 'weak',
  manual: 'weak',
};

export const EvidenceSchema = z.object({
  id: z.string(), // "E-0001" unique within a run
  type: EvidenceTypeSchema,
  tier: EvidenceTierSchema,
  ref: z.string(), // "TPL-HEADERS-01", "test:V6.2.1 min length", "dast:headers.csp", "finding:F-0012", "ai-review:V8.2.2"
  summary: z.string(), // one sentence, plain language
  passed: z.boolean(),
  tool: z.string().optional(), // "securevibe-dast", "node:test", "sast", "claude-opus-5"
  toolVersion: z.string().optional(),
  runId: z.string().optional(),
  capturedAt: z.string().optional(),
  location: z.object({ file: z.string(), line: z.number().int().optional() }).optional(),
  /** Short redacted excerpt of what was observed (<= 2 KB) and where the full raw output lives. */
  raw: z.object({ excerpt: z.string().max(2048).optional(), artifactPath: z.string().optional() }).optional(),
  aiReview: z
    .object({
      model: z.string(), // served model
      promptHash: z.string(),
      confidence: z.enum(['high', 'medium', 'low']),
      citationVerified: z.boolean(),
      /**
       * Every file the assessment cited, not just the first. `location` names one of them for display; a rebuild
       * may only carry this verdict forward when all of these are byte-identical, because a verdict formed from
       * three files says nothing once two of them have been rewritten.
       */
      citedFiles: z.array(z.string()).optional(),
    })
    .optional(),
  /** Who produced it: "rules", "claude-opus-5", "owner:<name>", a tool name... */
  producedBy: z.string().optional(),
  /**
   * Requirements this piece of evidence speaks to. A checker that already knows which requirements it verifies
   * (the configuration checks, for one) says so here, so the evaluation can credit them without the requirement
   * id having to appear in `ref`.
   */
  requirementIds: z.array(z.string()).optional(),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const RequirementStatusSchema = z.enum([
  'pass', // verified by strong/medium deterministic evidence
  'ai-assessed', // only AI-review evidence supports it (never counted as pass)
  'documented', // only generated documentation supports it
  'attested', // only a human attestation supports it
  'partial', // mixed evidence, or a deterministic check says partially met
  'fail', // a deterministic check failed or a mapped finding is open
  'not-applicable',
  'not-verified',
  'out-of-level',
]);
export type RequirementStatus = z.infer<typeof RequirementStatusSchema>;

/** One-sentence definitions rendered wherever a status appears. */
export const STATUS_DEFINITIONS: Record<RequirementStatus, string> = {
  pass: 'Verified by an automated test, a runtime probe, or two independent static checks.',
  'ai-assessed': 'Only an AI code review supports this. It is not counted as verified.',
  documented: 'A generated document describes this, but nothing verified that it is true in practice.',
  attested: 'A person confirmed this manually. It is recorded, not independently verified.',
  partial: 'Some checks passed and some did not, or the control is only partly in place.',
  fail: 'A check failed or an open finding contradicts this requirement.',
  'not-applicable': 'This requirement does not apply to this application as designed (reason given).',
  'not-verified': 'Nothing could verify this automatically. Instructions for a person are provided.',
  'out-of-level': 'This requirement belongs to a higher verification level than this application targets.',
};

export const VerificationClassSchema = z.enum([
  'automatable', // a probe/test/manifest control can prove it
  'ai-assistable', // needs judgement; AI review may assess, humans should confirm
  'doc-generated', // a document generated from source-of-truth constants describes it
  'scanner-clean', // best evidence is "no issues detected" by rules with partial coverage
  'manual-only', // can never be automated; always not-verified until a human attests
  'deployment-time', // only verifiable once the app is deployed (TLS, hosting, ops)
]);
export type VerificationClass = z.infer<typeof VerificationClassSchema>;

export const NotVerifiedReasonSchema = z.enum([
  'no-check-available',
  'check-skipped-offline',
  'check-skipped-dependencies-missing',
  'check-errored',
  'demo-mode',
  'requires-human',
  'requires-deployment',
  'model-declined',
  'citation-unverified',
  'low-confidence',
]);
export type NotVerifiedReason = z.infer<typeof NotVerifiedReasonSchema>;

export const ManualVerificationSchema = z.object({
  whoCanDo: z.enum(['owner', 'developer', 'security-professional', 'hosting-provider']),
  /** Plain yes/no question for owners, or steps for developers. */
  question: z.string().optional(),
  steps: z.array(z.string()).default([]),
  whatCountsAsEvidence: z.string().optional(),
  estimatedEffort: z.enum(['minutes', 'hour', 'day']).default('minutes'),
});
export type ManualVerification = z.infer<typeof ManualVerificationSchema>;

export const StandardIdSchema = z.enum(['asvs', 'aisvs', 'aisvs-appendix-c']);
export type StandardId = z.infer<typeof StandardIdSchema>;

export const RequirementResultSchema = z.object({
  id: z.string(), // "V6.2.1", "C2.1.3", "AC.4.1"
  standard: StandardIdSchema,
  chapterId: z.string(), // "V6", "C2", "AC.4"
  chapterName: z.string(),
  sectionId: z.string(),
  sectionName: z.string(),
  description: z.string(),
  level: z.number().int(),
  status: RequirementStatusSchema,
  verificationClass: VerificationClassSchema,
  notVerifiedReason: NotVerifiedReasonSchema.optional(),
  notApplicableReason: z.string().optional(),
  evidence: z.array(EvidenceSchema).default([]),
  rationale: z.string(), // why this status, one or two sentences
  findingIds: z.array(z.string()).default([]),
  remediation: z.string().optional(), // when fail/partial
  manualVerification: ManualVerificationSchema.optional(),
  assessedBy: z.array(z.enum(['rules', 'ai-review', 'manual'])).default([]),
  /** Plain-language explanation of the requirement (for non-experts). */
  plainLanguage: z.string().optional(),
  /** Deployment-time note when the status depends on how/where the app is hosted. */
  deploymentNote: z.string().optional(),
});
export type RequirementResult = z.infer<typeof RequirementResultSchema>;

export const StatusCountsSchema = z.object({
  pass: z.number().int().default(0),
  'ai-assessed': z.number().int().default(0),
  documented: z.number().int().default(0),
  attested: z.number().int().default(0),
  partial: z.number().int().default(0),
  fail: z.number().int().default(0),
  'not-applicable': z.number().int().default(0),
  'not-verified': z.number().int().default(0),
  'out-of-level': z.number().int().default(0),
});
export type StatusCounts = z.infer<typeof StatusCountsSchema>;

export const ChapterSummarySchema = z.object({
  id: z.string(),
  name: z.string(),
  counts: StatusCountsSchema,
});
export type ChapterSummary = z.infer<typeof ChapterSummarySchema>;

export const StandardSummarySchema = z.object({
  standard: StandardIdSchema,
  name: z.string(),
  version: z.string(),
  targetLevel: z.number().int(),
  targetLevelRule: z.string(), // plain-language sentence explaining why this level
  counts: StatusCountsSchema,
  byChapter: z.array(ChapterSummarySchema),
  /** Denominator: applicable requirements at the target level (excludes N/A and out-of-level). */
  applicableCount: z.number().int(),
  /** pass / applicableCount (percentage). Never includes ai-assessed, documented or attested. */
  verifiedPassPercent: z.number(),
  /** (pass + fail + partial) / applicableCount: how much automation could actually decide. */
  automatedCoveragePercent: z.number(),
  /** Count of applicable requirements that have any automated check path (from applicability rules). */
  automatableCount: z.number().int(),
  rating: z.enum(['good', 'needs-attention', 'at-risk']),
  ratingReason: z.string(),
});
export type StandardSummary = z.infer<typeof StandardSummarySchema>;

export const SbdEvaluatedEntrySchema = SbdChecklistEntrySchema.extend({
  /** Whether the implementation still matches the design (checked after the build). */
  verification: z.enum(['verified', 'design-only', 'not-verified', 'contradicted']).default('design-only'),
  verificationNote: z.string().optional(),
  evidenceIds: z.array(z.string()).default([]),
});
export type SbdEvaluatedEntry = z.infer<typeof SbdEvaluatedEntrySchema>;

export const SbdEvaluationSchema = z.object({
  framework: z.string(),
  version: z.string(),
  entries: z.array(SbdEvaluatedEntrySchema),
  /** Suggested scoring from the framework: Yes=0, N-A=0 (justified), No(Low)=1, No(Med)=2, No(High)=4. */
  score: z.number(),
  threshold: z.number(),
  criticalNo: z.array(z.string()),
  escalate: z.boolean(),
  escalationReasons: z.array(z.string()),
  /** How the escalation was handled when no AppSec team exists. */
  escalationHandling: z.string(),
  counts: z.object({ yes: z.number(), no: z.number(), 'n-a': z.number() }),
  criticalCounts: z.object({ yes: z.number(), no: z.number(), 'n-a': z.number() }),
  notApplicableIds: z.array(z.string()),
  /** The same controls re-evaluated under an internet deployment assumption. */
  deploymentTime: z.array(
    z.object({ id: z.string(), status: z.enum(['yes', 'no', 'n-a', 'deferred']), note: z.string() }),
  ),
  processSteps: z.array(
    z.object({
      step: z.number().int(),
      name: z.string(),
      completed: z.boolean(),
      performedBy: z.string(), // "rules", "claude-opus-5", "owner", "not performed"
      artifact: z.string().optional(),
      note: z.string().optional(),
    }),
  ),
  summary: z.string(),
});
export type SbdEvaluation = z.infer<typeof SbdEvaluationSchema>;

export const RecommendationSchema = z.object({
  id: z.string(),
  priority: z.enum(['high', 'medium', 'low']),
  title: z.string(),
  detail: z.string(),
  who: z.enum(['owner', 'developer', 'security-professional', 'hosting-provider']),
  effort: z.enum(['minutes', 'hour', 'day', 'more']).optional(),
  /**
   * When this has to be done, in the owner's terms — "before internet deployment", "before multi-team use".
   * Absent means now. An action waiting on something that has not happened must not sit above one that is due
   * today: an owner running an app on her own computer was told first to connect it to an organisation's central
   * sign-in system, and second to move its secrets into a hosting provider's secret manager, neither of which
   * she has.
   */
  dueBy: z.string().optional(),
  relatedRequirements: z.array(z.string()).default([]),
  relatedFindings: z.array(z.string()).default([]),
  relatedControls: z.array(z.string()).default([]),
});
export type Recommendation = z.infer<typeof RecommendationSchema>;

export const TraceabilityRowSchema = z.object({
  requirementId: z.string(), // SR-xx
  statement: z.string(),
  controls: z.array(z.string()), // template controls / patterns
  asvs: z.array(z.string()),
  aisvs: z.array(z.string()),
  sbd: z.array(z.string()),
  status: z.enum(['verified', 'partially-verified', 'not-verified', 'failing']),
});
export type TraceabilityRow = z.infer<typeof TraceabilityRowSchema>;

export const HumanReviewSchema = z.object({
  performed: z.boolean(),
  reviewedBy: z.string().optional(),
  reviewedAt: z.string().optional(),
  filesReviewed: z.array(z.string()).default([]),
  note: z.string().optional(),
});
export type HumanReview = z.infer<typeof HumanReviewSchema>;

export const ComplianceResultSchema = z.object({
  reportSchemaVersion: z.string(),
  generatedAt: z.string(),
  runId: z.string(),
  previousRunId: z.string().optional(),
  sbd: SbdEvaluationSchema,
  asvs: z.object({ summary: StandardSummarySchema, results: z.array(RequirementResultSchema) }),
  aisvs: z.object({ summary: StandardSummarySchema, results: z.array(RequirementResultSchema) }).optional(),
  appendixC: z.object({ summary: StandardSummarySchema, results: z.array(RequirementResultSchema) }).optional(),
  traceability: z.array(TraceabilityRowSchema),
  recommendations: z.array(RecommendationSchema),
  manualVerification: z.array(
    z.object({ requirementId: z.string(), standard: StandardIdSchema, manual: ManualVerificationSchema }),
  ),
  humanReview: HumanReviewSchema,
  methodology: z.string(),
  limitations: z.array(z.string()),
  /** Status transitions vs the previous run, when available. */
  changesSincePrevious: z
    .object({
      improved: z.array(z.string()),
      regressed: z.array(z.string()),
      newFindings: z.number().int(),
      fixedFindings: z.number().int(),
    })
    .optional(),
  overall: z.object({
    rating: z.enum(['good', 'needs-attention', 'at-risk']),
    headline: z.string(), // one plain-language sentence
    /** Deployment-gated statement: "Suitable for use on this computer with the 2 actions below…" */
    canIUseIt: z.string(),
    topActions: z.array(RecommendationSchema).max(5),
  }),
});
export type ComplianceResult = z.infer<typeof ComplianceResultSchema>;

export function emptyCounts(): StatusCounts {
  return {
    pass: 0,
    'ai-assessed': 0,
    documented: 0,
    attested: 0,
    partial: 0,
    fail: 0,
    'not-applicable': 0,
    'not-verified': 0,
    'out-of-level': 0,
  };
}
