import { z } from 'zod';
import { DesignArtifactsSchema } from './design.js';
import { TriageSchema } from './findings.js';
import { RunSummarySchema } from './pipeline.js';
import { PartialDesignProfileSchema } from './profile.js';

export const ProjectStatusSchema = z.enum(['draft', 'designed', 'building', 'built', 'failed']);
export type ProjectStatus = z.infer<typeof ProjectStatusSchema>;

/** A human answer to a "not-verified" requirement (recorded as weak `manual` evidence, status `attested`). */
export const AttestationSchema = z.object({
  id: z.string(),
  requirementId: z.string(), // "V6.1.1", "C12.1.1", "AC.4.1", or an SbD id "MT-06"
  standard: z.enum(['asvs', 'aisvs', 'aisvs-appendix-c', 'sbd']),
  /**
   * "not-applicable" is an answer with a reason: the control stays visible, reads "not applicable, because ...",
   * and the reports name who decided and when. It is not a dismiss button: the API refuses it without a note.
   */
  result: z.enum(['yes', 'no', 'not-sure', 'not-applicable']),
  note: z.string().max(2000).default(''),
  attestedBy: z.string(),
  attestedAt: z.string(),
  evidenceLink: z.string().optional(),
});
export type Attestation = z.infer<typeof AttestationSchema>;

/** A persisted decision about a finding fingerprint (survives rebuilds). */
export const FindingDecisionSchema = z.object({
  fingerprint: z.string(),
  status: z.enum(['accepted', 'false-positive']),
  triage: TriageSchema,
});
export type FindingDecision = z.infer<typeof FindingDecisionSchema>;

export const HumanCodeReviewSchema = z.object({
  reviewedBy: z.string(),
  reviewedAt: z.string(),
  filesReviewed: z.array(z.string()),
  codeTreeHash: z.string(), // the tree that was reviewed
  note: z.string().optional(),
});
export type HumanCodeReview = z.infer<typeof HumanCodeReviewSchema>;

/**
 * "Let's check a few things": Claude's follow-up questions and suggested features for the owner's answers, with what
 * the owner did about each one. Kept with the project so the reports can show that a person made these decisions.
 */
export const RefinementQuestionSchema = z.object({
  id: z.string(),
  question: z.string(),
  why: z.string(),
  /** The answer this question sets, when SecureVibe can apply it. */
  field: z.string().optional(),
  options: z.array(z.object({ label: z.string(), value: z.string() })).default([]),
  answered: z.boolean().default(false),
  /** The value the owner chose (or their own words when the question only records a note). */
  answer: z.string().optional(),
});
export type RefinementQuestion = z.infer<typeof RefinementQuestionSchema>;

export const RefinementSuggestionSchema = z.object({
  id: z.string(),
  title: z.string(),
  detail: z.string(),
  field: z.string(),
  value: z.string(),
  /** null until the owner decides. */
  accepted: z.boolean().nullable().default(null),
});
export type RefinementSuggestion = z.infer<typeof RefinementSuggestionSchema>;

export const RefinementSchema = z.object({
  performedBy: z.enum(['claude', 'skipped']),
  model: z.string().optional(),
  performedAt: z.string(),
  summary: z.string(),
  questions: z.array(RefinementQuestionSchema).default([]),
  features: z.array(RefinementSuggestionSchema).default([]),
  skippedReason: z.string().optional(),
  /** Set when the owner chose to move on without going through them. */
  dismissedAt: z.string().optional(),
});
export type Refinement = z.infer<typeof RefinementSchema>;

/**
 * The build plan: what Claude intends to write, feature by feature, for the owner to approve before any code is
 * written. After the build, each feature is checked against what actually exists (pages, records, tests).
 */
export const PlannedFeatureSchema = z.object({
  id: z.string(),
  title: z.string(),
  /** What a person can do once it exists, in plain words. */
  whatItDoes: z.string(),
  /** Page paths the feature adds, e.g. "/research", "/research/new". */
  pages: z.array(z.string()).default([]),
  /** Record types it stores, by name, e.g. "research_topics". */
  records: z.array(z.string()).default([]),
  /** Names of the tests that will prove it, e.g. "RS-01 denies anonymous visitors". */
  tests: z.array(z.string()).default([]),
  /** The owner may leave a feature out of the build. */
  wanted: z.boolean().default(true),
});
export type PlannedFeature = z.infer<typeof PlannedFeatureSchema>;

export const BuildPlanSchema = z.object({
  createdAt: z.string(),
  model: z.string().optional(),
  /** The design (profile hash) the plan was written for; a changed design needs a new plan. */
  designHash: z.string(),
  summary: z.string(),
  features: z.array(PlannedFeatureSchema).default([]),
  /** Roughly how many working steps the writing will take, from the plan itself. */
  estimatedSteps: z.number().int().optional(),
  approvedAt: z.string().optional(),
});
export type BuildPlan = z.infer<typeof BuildPlanSchema>;

/** Where an app's code comes from: written by SecureVibe, or uploaded by the owner to be checked. */
export const ProjectOriginSchema = z.object({
  kind: z.enum(['generated', 'uploaded']),
  /** Uploaded apps: the owner said AI tools helped write the code (AISVS Appendix C then applies). */
  aiAssisted: z.boolean().optional(),
  upload: z
    .object({
      uploadedAt: z.string(),
      files: z.number().int(),
      bytes: z.number().int(),
      /** Files left out on purpose (dependencies, build output, secrets files, too large). */
      skipped: z.number().int(),
      version: z.number().int(),
    })
    .optional(),
});
export type ProjectOrigin = z.infer<typeof ProjectOriginSchema>;

/** What "Update to the latest template" changed, so the results page can say what happened. */
export const TemplateUpgradeSchema = z.object({
  at: z.string(),
  templateVersion: z.string(),
  templateHash: z.string(),
  updated: z.array(z.string()).default([]),
  added: z.array(z.string()).default([]),
  removed: z.array(z.string()).default([]),
  /** Template files that carry your own or Claude's changes: left as they were, so the template's newer version was not applied there. */
  kept: z.array(z.string()).default([]),
  envKeysAdded: z.array(z.string()).default([]),
  warnings: z.array(z.string()).default([]),
});
export type TemplateUpgrade = z.infer<typeof TemplateUpgradeSchema>;

export const ProjectSchema = z.object({
  id: z.string(), // "p_" + 10 base32 chars
  name: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
  /** Partial while the wizard is in progress; validated fully before design derivation. */
  profile: PartialDesignProfileSchema,
  profileHash: z.string().optional(),
  /** 0-based index of the wizard step the user reached. */
  wizardStep: z.number().int().min(0).default(0),
  design: DesignArtifactsSchema.optional(),
  status: ProjectStatusSchema.default('draft'),
  lastRunId: z.string().optional(),
  runs: z.array(RunSummarySchema).default([]),
  /** True when the profile changed after the last design/build (SbD step 10: design-drift watch). */
  designStale: z.boolean().default(false),
  buildStale: z.boolean().default(false),
  /** Version counter for the generated app folder (app/ is versioned as app-v<N>/ on rebuild). */
  appVersion: z.number().int().default(0),
  attestations: z.array(AttestationSchema).default([]),
  findingDecisions: z.array(FindingDecisionSchema).default([]),
  humanCodeReview: HumanCodeReviewSchema.optional(),
  /** Owner-acknowledged escalation (SbD risk triage) with timestamp. */
  escalationAcknowledgedAt: z.string().optional(),
  /** Spending cap for LLM usage per build, in US dollars (user-set; default from settings). */
  spendingCapUsd: z.number().optional(),
  /** Set when the owner archived the app: hidden from the main list until restored. */
  archivedAt: z.string().optional(),
  /** Absent for apps SecureVibe built before uploads existed (they are "generated"). */
  origin: ProjectOriginSchema.optional(),
  /** Set on an app made with "Copy": the answers and design came from another app, nothing built did. */
  copiedFrom: z.object({ projectId: z.string(), name: z.string(), at: z.string() }).optional(),
  /** Claude's follow-up questions about the answers, and what the owner decided (absent until asked for). */
  refinement: RefinementSchema.optional(),
  /** The feature plan for the next build, once prepared (and approved) — see BuildPlanSchema. */
  buildPlan: BuildPlanSchema.optional(),
  /** The last "Update to the latest template", if any. */
  lastUpgrade: TemplateUpgradeSchema.optional(),
  /** Worked out by the API from the app's provenance and the current template; never stored. */
  templateOutdated: z.boolean().optional(),
});
export type Project = z.infer<typeof ProjectSchema>;

export function isUploadedApp(project: { origin?: ProjectOrigin }): boolean {
  return project.origin?.kind === 'uploaded';
}
