/**
 * HTTP API contract between the web app and the server. All routes are under /api and require the
 * local session cookie (obtained by visiting /auth/token?t=<startup token> once). Mutating requests
 * additionally require the X-CSRF-Token header (value from GET /api/status) and an allowed Origin.
 */
import { z } from 'zod';
import { DesignArtifactsSchema, PeerReviewSchema } from './design.js';
import { FindingSchema, TriageSchema } from './findings.js';
import { CostEstimateSchema, PipelineRunSchema, RunModeSchema, StageIdSchema, ToolCoverageSchema } from './pipeline.js';
import { DesignProfileSchema, PartialDesignProfileSchema } from './profile.js';
import { AttestationSchema, BuildPlanSchema, ProjectSchema, RefinementSchema } from './project.js';

export const ApiErrorSchema = z.object({
  error: z.object({
    code: z.string(), // "validation_error", "not_found", "llm_unavailable", "forbidden", "rate_limited", "internal", "conflict"
    message: z.string(), // safe, user-readable
    details: z.unknown().optional(),
    correlationId: z.string().optional(),
  }),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;

export const PreflightCheckSchema = z.object({
  id: z.enum(['node-version', 'api-key', 'npm-registry', 'workspace-writable', 'port', 'disk-space']),
  ok: z.boolean(),
  title: z.string(),
  detail: z.string(), // plain language, includes how to fix when not ok
  blocking: z.boolean(),
});
export type PreflightCheck = z.infer<typeof PreflightCheckSchema>;

/** GET /api/status */
export const StatusResponseSchema = z.object({
  version: z.string(),
  nodeVersion: z.string(),
  llm: z.object({
    configured: z.boolean(), // an API key / credential is available
    provider: z.string(), // "anthropic" | "null" | "scripted"
    model: z.string(),
    previewMode: z.boolean(), // true when no credential or AI is switched off → "Preview without AI"
    message: z.string(), // plain-language explanation
    /** Why AI is off although a key exists: the Settings switch, or SECUREVIBE_AI=off (which the switch cannot override). */
    switchedOff: z.enum(['setting', 'environment']).optional(),
  }),
  preflight: z.array(PreflightCheckSchema),
  tools: z.array(ToolCoverageSchema), // availability of optional external scanners
  csrfToken: z.string(),
  workspaceDir: z.string(),
  /** Which AI services have a key, and which can run builds today (Settings → "Your AI service"). */
  aiServices: z.array(
    z.object({
      service: z.enum(['anthropic', 'openai', 'google']),
      label: z.string(),
      configured: z.boolean(),
      endsWith: z.string().optional(),
      usableForBuilds: z.boolean(),
      consoleUrl: z.string(),
      fromEnvironment: z.boolean().optional(),
    }),
  ),
  settings: z.object({
    model: z.string(),
    generationEffort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']),
    reviewEffort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']),
    defaultSpendingCapUsd: z.number(),
    maxFixRounds: z.number().int(),
    storeFullPrompts: z.boolean(),
    aiEnabled: z.boolean(),
    saveCredits: z.boolean(),
    notifyOnFinish: z.boolean(),
    /** The AI service everything uses unless a step below says otherwise; it needs a key (see aiServices). */
    aiService: z.enum(['anthropic', 'openai', 'google']),
    /** Which service does which step ('default' = the one above). */
    aiServiceFor: z.object({
      write: z.enum(['default', 'anthropic', 'openai', 'google']),
      review: z.enum(['default', 'anthropic', 'openai', 'google']),
      questions: z.enum(['default', 'anthropic', 'openai', 'google']),
    }),
    /** The optional experimental AI scanner: off unless the owner switched it on (it costs money). */
    nanoAnalyzer: z.object({
      enabled: z.boolean(),
      scriptPath: z.string(),
      model: z.string(),
      minConfidence: z.number(),
      /** Whether a key for the service it needs is present; false means it will be skipped. */
      keyPresent: z.boolean(),
    }),
    /** The model builds use right now (Save credits applied). */
    effectiveModel: z.string(),
  }),
});
export type StatusResponse = z.infer<typeof StatusResponseSchema>;

/** PUT /api/settings (advanced; "Reset to recommended" restores defaults) */
export const UpdateSettingsRequestSchema = z.object({
  model: z.string().optional(),
  generationEffort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).optional(),
  reviewEffort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).optional(),
  defaultSpendingCapUsd: z.number().min(1).max(500).optional(),
  maxFixRounds: z.number().int().min(0).max(3).optional(),
  storeFullPrompts: z.boolean().optional(),
  aiEnabled: z.boolean().optional(),
  saveCredits: z.boolean().optional(),
  notifyOnFinish: z.boolean().optional(),
  aiService: z.enum(['anthropic', 'openai', 'google']).optional(),
  /** All three values together (a partial object would clear the ones left out). */
  aiServiceFor: z
    .object({
      write: z.enum(['default', 'anthropic', 'openai', 'google']),
      review: z.enum(['default', 'anthropic', 'openai', 'google']),
      questions: z.enum(['default', 'anthropic', 'openai', 'google']),
    })
    .optional(),
  /** All four values together, like aiServiceFor above. */
  nanoAnalyzer: z
    .object({
      enabled: z.boolean(),
      scriptPath: z.string().max(400),
      model: z.string().min(1).max(80),
      minConfidence: z.number().min(0).max(1),
    })
    .optional(),
  reset: z.boolean().optional(),
});

/** POST /api/projects/:id/plan — ask Claude for the feature plan; POST .../plan/approve — the owner's choice */
export const PlanResponseSchema = z.object({ project: ProjectSchema, plan: BuildPlanSchema });
export const PlanApproveRequestSchema = z.object({
  /** Features to build; the rest are marked as left out. */
  featureIds: z.array(z.string()).max(40),
});

/** POST /api/projects/:id/refine — ask Claude for follow-up questions and feature suggestions */
export const RefineResponseSchema = z.object({ project: ProjectSchema, refinement: RefinementSchema });

/** POST /api/projects/:id/refine/decisions — the owner's answers and which suggested features to add */
export const RefineDecisionsRequestSchema = z.object({
  answers: z.array(z.object({ questionId: z.string(), value: z.string().max(400) })).max(20).default([]),
  features: z.array(z.object({ suggestionId: z.string(), accepted: z.boolean() })).max(20).default([]),
  /** Move on without answering the rest; recorded in the reports. */
  dismiss: z.boolean().optional(),
});

/** PUT /api/settings/ai-key — store or remove one service's key (the key is never returned by any route) */
export const AiKeyRequestSchema = z.object({
  service: z.enum(['anthropic', 'openai', 'google']),
  /** Omit or send an empty string together with remove: true to take the key out. */
  key: z.string().max(400).optional(),
  remove: z.boolean().optional(),
});

/** POST /api/projects */
export const CreateProjectRequestSchema = z.object({
  name: z.string().min(1).max(60),
  mode: z.enum(['guided', 'quick']).default('guided'),
  /** Start from an example (id from GET /api/examples). */
  exampleId: z.string().optional(),
  /** Check an app the owner already has, instead of building one. */
  uploaded: z.object({ aiAssisted: z.boolean() }).optional(),
});
export type CreateProjectRequest = z.infer<typeof CreateProjectRequestSchema>;

/** GET /api/examples */
export const ExampleProjectSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  /** Small enough to build without AI: the way to see the whole process before spending anything. */
  free: z.boolean().optional(),
  profile: DesignProfileSchema,
});
export type ExampleProject = z.infer<typeof ExampleProjectSchema>;

/** GET /api/projects → ProjectListItem[] */
export const ProjectListItemSchema = ProjectSchema.pick({
  id: true,
  name: true,
  createdAt: true,
  updatedAt: true,
  status: true,
  wizardStep: true,
  lastRunId: true,
  designStale: true,
  buildStale: true,
  archivedAt: true,
  origin: true,
  templateOutdated: true,
});
export type ProjectListItem = z.infer<typeof ProjectListItemSchema>;

/** PUT /api/projects/:id/profile — save (partial) wizard answers */
export const SaveProfileRequestSchema = z.object({
  profile: PartialDesignProfileSchema,
  wizardStep: z.number().int().min(0).optional(),
});
export type SaveProfileRequest = z.infer<typeof SaveProfileRequestSchema>;

/** POST /api/projects/:id/quick-infer — Quick mode: infer the remaining profile from a description.
 *  The high-consequence answers (data categories, audience, deployment) are always asked explicitly and passed in. */
export const QuickInferRequestSchema = z.object({
  description: z.string().min(10).max(4000),
  name: z.string().min(1).max(60).optional(),
  known: z.object({
    dataCategories: z.array(z.string()).optional(),
    audience: z.string().optional(),
    deploymentTarget: z.string().optional(),
  }),
});
export const QuickInferResponseSchema = z.object({
  profile: DesignProfileSchema,
  inferredFields: z.array(z.string()),
  /** Fields the model could not support with evidence from the text: shown as explicit questions, never preselected. */
  needsConfirmation: z.array(z.object({ field: z.string(), question: z.string(), evidence: z.string().optional() })),
  assumptions: z.array(z.string()), // "We assumed only your team will use it."
  screening: z.object({ flagged: z.boolean(), note: z.string().optional() }).default({ flagged: false }),
});
export type QuickInferResponse = z.infer<typeof QuickInferResponseSchema>;

/** POST /api/projects/:id/design — derive design artifacts (SbD steps 2-4, 6, 7, 8). */
export const DeriveDesignResponseSchema = z.object({
  project: ProjectSchema,
  design: DesignArtifactsSchema,
});
export type DeriveDesignResponse = z.infer<typeof DeriveDesignResponseSchema>;

/** POST /api/projects/:id/design/peer-review — SbD step 5 (AI second opinion; skipped in preview mode) */
export const PeerReviewResponseSchema = z.object({ peerReview: PeerReviewSchema, design: DesignArtifactsSchema });

/** POST /api/projects/:id/design/peer-review/decisions — answers to clarification questions / dismissals */
export const PeerReviewDecisionsRequestSchema = z.object({
  decisions: z.array(
    z.object({
      suggestionId: z.string(),
      accepted: z.boolean(),
      optionIndex: z.number().int().optional(),
      dismissReason: z.string().max(500).optional(),
    }),
  ),
});

/** POST /api/projects/:id/escalation/acknowledge — owner acknowledges the extra-care review (SbD step 6/7) */

/** GET /api/projects/:id/estimate → CostEstimate */
export const EstimateResponseSchema = z.object({
  estimate: CostEstimateSchema,
  /** One-time code for approving this build, valid for an hour, for this session, app and design only. */
  approvalCode: z.string(),
});

/** POST /api/projects/:id/runs — start a pipeline run */
export const StartRunRequestSchema = z.object({
  mode: RunModeSchema.default('full'),
  /** Explicit human approval (AISVS C9.2 / Appendix C AC.4): the owner ticked the box on the build page... */
  approved: z.literal(true),
  /** ...for the estimate they were shown: the code from GET /estimate, checked and used up by the server. */
  approvalCode: z.string().min(16).max(128),
  spendingCapUsd: z.number().min(1).max(500).optional(),
  /** Findings (by id from the last run) the user asked Claude to fix in an extra round. */
  fixFindingIds: z.array(z.string()).optional(),
  /** Run without any AI call even when AI is on (a free re-check). */
  withoutAi: z.boolean().optional(),
  /**
   * Run only these checks (the Security page's "run this one again"). Everything else is recorded as not run this
   * time, and the compliance report is left as the last full check made it.
   */
  checks: z.array(StageIdSchema).min(1).max(20).optional(),
});
export const StartRunResponseSchema = z.object({ run: PipelineRunSchema });

/**
 * GET /api/projects/:id/checks — the Security page: every check that can be run on its own, with the last time it
 * actually ran and what it said. A check that was left out of a partial run keeps the result of the run that did
 * run it, so the page never shows a gap where there is a real result.
 */
export const CheckStatusSchema = z.object({
  id: StageIdSchema,
  title: z.string(),
  /** What this check looks at, in plain language. */
  covers: z.string(),
  status: z.enum(['passed', 'failed', 'warning', 'skipped', 'never-run']),
  summary: z.string(),
  /** When the check last ran, and in which run. */
  ranAt: z.string().optional(),
  runId: z.string().optional(),
  /** Problems this check found in that run, by severity. */
  findingCounts: z.record(z.string(), z.number()).optional(),
});
export const ChecksResponseSchema = z.object({
  checks: z.array(CheckStatusSchema),
  /** The last run in which every check ran: the one the compliance report and the reports come from. */
  lastFullCheck: z.object({ runId: z.string(), finishedAt: z.string().optional(), status: z.string() }).optional(),
  /** True while a run of this project is going on, so the page offers to watch it instead of starting another. */
  running: z.boolean(),
});
export type CheckStatus = z.infer<typeof CheckStatusSchema>;
export type ChecksResponse = z.infer<typeof ChecksResponseSchema>;

/**
 * PUT /api/projects/:id/appearance — change how an app looks without rebuilding it. A theme is colour only, so
 * nothing is generated, nothing is checked again and no approval is needed.
 */
export const AppearanceRequestSchema = z.object({ theme: z.enum(['calm', 'warm', 'forest', 'contrast']) });
export const AppearanceResponseSchema = z.object({
  theme: z.enum(['calm', 'warm', 'forest', 'contrast']),
  /** True when the app is already built, so the change takes effect the next time it starts. */
  applied: z.boolean(),
  message: z.string(),
});

export type AppearanceResponse = z.infer<typeof AppearanceResponseSchema>;

/** GET /api/runs/:id → PipelineRun ; GET /api/runs/:id/events — SSE stream of ProgressEvent (event: "progress"). */
/** POST /api/runs/:id/cancel */

/** POST /api/projects/:id/findings/:findingId/decision — "I understand, leave it" / false positive */
export const FindingDecisionRequestSchema = z.object({
  status: z.enum(['accepted', 'false-positive', 'open']),
  triage: TriageSchema.omit({ by: true, at: true }).optional(),
});

/** GET /api/projects/:id/findings → Finding[] (latest run, with persisted decisions applied) */
export const FindingsResponseSchema = z.object({ findings: z.array(FindingSchema) });

/** POST /api/projects/:id/attestations ; DELETE /api/projects/:id/attestations/:attestationId */
export const AttestationRequestSchema = AttestationSchema.omit({ id: true, attestedAt: true });

/** POST /api/projects/:id/human-review — record that a named person reviewed the security-critical files */
export const HumanReviewRequestSchema = z.object({
  reviewedBy: z.string().min(1).max(80),
  note: z.string().max(1000).optional(),
});

/** GET /api/projects/:id/artifacts → ArtifactRef[] ; GET /api/projects/:id/artifacts/:name → file */
/** GET /api/projects/:id/app/run-instructions → RunInstructions */
export const RunInstructionsSchema = z.object({
  appDir: z.string(),
  steps: z.array(
    z.object({
      title: z.string(),
      command: z.string().optional(),
      expected: z.string().optional(),
      troubleshooting: z.string().optional(),
    }),
  ),
  /** One-time admin password created at scaffold time (shown once; also written to app/FIRST-LOGIN.txt). */
  firstLogin: z
    .object({ url: z.string(), email: z.string(), note: z.string() })
    .optional(),
  needsAuthenticatorApp: z.boolean(),
  unfinished: z.array(z.string()), // "Payments: placeholder checkout page — needs a provider account"
});
export type RunInstructions = z.infer<typeof RunInstructionsSchema>;

/** GET /api/frameworks/summary */
export const FrameworkSummarySchema = z.object({
  sbd: z.object({ version: z.string(), controls: z.number(), critical: z.number() }),
  asvs: z.object({ version: z.string(), requirements: z.number(), chapters: z.number() }),
  aisvs: z.object({ version: z.string(), requirements: z.number(), chapters: z.number() }),
  appendixC: z.object({ version: z.string(), requirements: z.number(), families: z.number() }),
});
export type FrameworkSummary = z.infer<typeof FrameworkSummarySchema>;

/** The wizard's step list (shared so server-side validation and UI agree). Sub-screens live inside steps. */
export const WIZARD_STEPS = [
  { id: 'about', title: 'What are you building?' },
  { id: 'users', title: 'Who will use it?' },
  { id: 'data', title: 'What information will it handle?' },
  { id: 'features', title: 'Features & connections' },
  { id: 'deployment', title: 'Where will it run?' },
  { id: 'summary', title: "Here's what we'll build" },
  { id: 'build', title: 'Build' },
  { id: 'results', title: 'Results' },
] as const;
export type WizardStepId = (typeof WIZARD_STEPS)[number]['id'];

/** GET /api/metrics?days=7|30|90 — the Dashboard: AI spending, builds, security events and open findings. */
const CountSchema = z.object({ key: z.string(), label: z.string(), count: z.number(), usd: z.number().optional() });
export const MetricsResponseSchema = z.object({
  days: z.number().int(),
  from: z.string(),
  generatedAt: z.string(),
  ai: z.object({
    totalUsd: z.number(),
    calls: z.number().int(),
    failedCalls: z.number().int(),
    inputTokens: z.number().int(),
    outputTokens: z.number().int(),
    /** Share of prompt tokens read from the cache (cheaper), 0–1. */
    cacheShare: z.number(),
    byPurpose: z.array(CountSchema),
    byApp: z.array(CountSchema),
    byModel: z.array(CountSchema),
    byDay: z.array(z.object({ day: z.string(), usd: z.number(), calls: z.number().int() })),
  }),
  builds: z.object({
    total: z.number().int(),
    byStatus: z.array(CountSchema),
    medianMinutes: z.number().nullable(),
    averageUsd: z.number().nullable(),
    maxUsd: z.number().nullable(),
    recent: z.array(
      z.object({
        runId: z.string(),
        projectId: z.string(),
        appName: z.string(),
        mode: z.string(),
        status: z.string(),
        startedAt: z.string(),
        minutes: z.number().nullable(),
        usd: z.number(),
        spendingCapUsd: z.number().optional(),
        openFindings: z.number().int(),
      }),
    ),
  }),
  security: z.object({
    signIns: z.number().int(),
    refusals: z.number().int(),
    lastSignInAt: z.string().nullable(),
    byEvent: z.array(CountSchema),
    byDay: z.array(z.object({ day: z.string(), refusals: z.number().int(), signIns: z.number().int() })),
    recent: z.array(z.object({ ts: z.string(), event: z.string(), label: z.string(), method: z.string().optional(), path: z.string().optional(), status: z.number().optional() })),
    /** Security events are recorded from the first start after this feature was added. */
    recordingSince: z.string().nullable(),
  }),
  findings: z.object({
    open: z.array(CountSchema),
    byApp: z.array(z.object({ projectId: z.string(), appName: z.string(), open: z.number().int(), critical: z.number().int(), high: z.number().int() })),
  }),
});
export type MetricsResponse = z.infer<typeof MetricsResponseSchema>;

/** GET /api/projects/:id/verification — everything the human verification wizard walks through. */
export const VerificationItemSchema = z.object({
  requirementId: z.string(),
  standard: z.enum(['asvs', 'aisvs', 'aisvs-appendix-c']),
  chapterName: z.string(),
  description: z.string(),
  plainLanguage: z.string().optional(),
  /** The requirement's status in the latest build. */
  status: z.string(),
  whoCanDo: z.enum(['owner', 'developer', 'security-professional', 'hosting-provider']),
  question: z.string().optional(),
  steps: z.array(z.string()),
  whatCountsAsEvidence: z.string().optional(),
  estimatedEffort: z.enum(['minutes', 'hour', 'day']),
  answer: AttestationSchema.optional(),
  /** Documents this check asks you to read, found on disk. `openable` is false for files that hold secrets. */
  documents: z
    .array(z.object({ path: z.string(), where: z.enum(['app', 'project', 'securevibe']), openable: z.boolean() }))
    .default([]),
});
export type VerificationItem = z.infer<typeof VerificationItemSchema>;

export const VerificationResponseSchema = z.object({
  runId: z.string(),
  builtAt: z.string(),
  suggestedName: z.string(),
  codeReview: z.object({
    /** Root folder the paths are relative to (shown so a reviewer can find the files). */
    root: z.string().nullable(),
    files: z.array(z.string()),
    reviewedBy: z.string().optional(),
    reviewedAt: z.string().optional(),
    note: z.string().optional(),
    /** The recorded review matches the files as they are now. */
    current: z.boolean(),
  }),
  items: z.array(VerificationItemSchema),
  /** Reports can be refreshed with the answers without running anything again. */
  canRefresh: z.boolean(),
  /** Answers or a code review were recorded after the reports were last written. */
  reportsOutdated: z.boolean(),
  /** SecureVibe's own self-assessment: re-checked from the command line, not from the web app. */
  selfAssessment: z.boolean(),
});
export type VerificationResponse = z.infer<typeof VerificationResponseSchema>;

// ---- app versions and what changed between them -------------------------------------------------------------

/** One version of the built app: the current `app/` or an archived `app-v<N>/`. */
export const AppVersionSchema = z.object({
  /** 'current' or 'v<N>'. */
  id: z.string(),
  label: z.string(),
  runId: z.string().optional(),
  builtAt: z.string().optional(),
  templateVersion: z.string().optional(),
});
export type AppVersion = z.infer<typeof AppVersionSchema>;
export const VersionsResponseSchema = z.object({ versions: z.array(AppVersionSchema) });

export const DiffFileSchema = z.object({
  path: z.string(),
  kind: z.enum(['added', 'removed', 'changed']),
  /** Where the file came from, per the newer version's provenance (or the older one's for removed files). */
  origin: z.string().optional(),
  binary: z.boolean().default(false),
  /** Settings files hold secrets: the fact that they changed is shown, the contents never. */
  secret: z.boolean().default(false),
  linesAdded: z.number().int().default(0),
  linesRemoved: z.number().int().default(0),
});
export type DiffFile = z.infer<typeof DiffFileSchema>;

export const FindingBriefSchema = z.object({ id: z.string(), fingerprint: z.string(), severity: z.string(), ruleId: z.string(), title: z.string() });

export const VersionDiffSchema = z.object({
  from: AppVersionSchema,
  to: AppVersionSchema,
  files: z.array(DiffFileSchema),
  /** True when more files changed than are listed. */
  truncated: z.boolean().default(false),
  /** How the checks came out, when both versions have a finished run. */
  results: z
    .object({
      findingsNew: z.array(FindingBriefSchema),
      findingsResolved: z.array(FindingBriefSchema),
      findingsStillOpen: z.number().int(),
      asvs: z.object({ before: z.number(), after: z.number() }).optional(),
      aisvs: z.object({ before: z.number(), after: z.number() }).optional(),
      tests: z.object({ before: z.object({ total: z.number(), passed: z.number() }), after: z.object({ total: z.number(), passed: z.number() }) }).optional(),
    })
    .optional(),
});
export type VersionDiff = z.infer<typeof VersionDiffSchema>;

export const FileDiffResponseSchema = z.object({
  path: z.string(),
  kind: z.enum(['added', 'removed', 'changed']),
  unified: z.string(),
  truncated: z.boolean().default(false),
});
export type FileDiffResponse = z.infer<typeof FileDiffResponseSchema>;

/** GET /api/projects/:id/document?path=… — one document a human check refers to. */
export const DocumentResponseSchema = z.object({
  path: z.string(),
  where: z.enum(['app', 'project', 'securevibe']),
  text: z.string(),
});
export type DocumentResponse = z.infer<typeof DocumentResponseSchema>;

/**
 * GET /api/projects/:id/app/file?path=&version= → AppFileResponse
 *
 * The contents of one file of the generated app, so a finding can be read in place instead of hunting for the file
 * on disk. Read-only, confined to the app folder, and files that hold secrets are never sent.
 */
export const AppFileResponseSchema = z.object({
  /** Path relative to the app folder, exactly as findings report it. */
  path: z.string(),
  /** Which version of the app this came from ("current", "v3", …). */
  version: z.string(),
  /** The absolute folder the file lives in, so a person can open it in Finder or an editor. */
  appDir: z.string(),
  /** The file's text. Empty when `notShown` explains why there is nothing to show. */
  text: z.string(),
  /** Total number of lines in the file (before any truncation). */
  lineCount: z.number().int(),
  /** True when only the first part of the file is included. */
  truncated: z.boolean().default(false),
  /** Where the file came from: template, expanded, ai-generated, ai-fixed, user. */
  origin: z.string().optional(),
  /** Plain-language reason the contents are not shown (secrets, not a text file, too large). */
  notShown: z.string().optional(),
});
export type AppFileResponse = z.infer<typeof AppFileResponseSchema>;
