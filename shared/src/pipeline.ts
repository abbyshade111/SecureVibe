/**
 * Pipeline run model and progress events streamed to the UI.
 */
import { z } from 'zod';
import { ComplianceResultSchema } from './compliance.js';
import { FindingSchema } from './findings.js';

export const STAGE_IDS = [
  'design-freeze',
  'scaffold',
  'generate',
  'install',
  'typecheck',
  'lint',
  'unit-tests',
  'sast',
  'secrets',
  'deps',
  'config',
  'dast',
  'external',
  'ai-review',
  'fix',
  'compliance',
  'reports',
] as const;
/**
 * The checks the owner can run again on their own from the Security page. They cost nothing and need no AI: the
 * steps that write code, spend money or decide compliance are not in the list, because running one of those alone
 * would either cost money without being asked or produce a verdict from a fraction of the evidence.
 */
export const RERUNNABLE_CHECKS = ['typecheck', 'lint', 'unit-tests', 'sast', 'secrets', 'deps', 'config', 'dast', 'external'] as const;

export const StageIdSchema = z.enum(STAGE_IDS);
export type StageId = z.infer<typeof StageIdSchema>;

/** Plain-language descriptions shown while a stage runs (kept here so server and web agree). */
export const STAGE_DESCRIPTIONS: Record<StageId, { title: string; running: string; why: string }> = {
  'design-freeze': {
    title: 'Finalising your design',
    running: 'Writing the design documents, decisions and the security rules the code generator must follow…',
    why: 'This is the hand-off from design to development (Secure by Design steps 8 and 9).',
  },
  scaffold: {
    title: 'Laying the secure foundation',
    running: 'Copying the hardened starter application and switching on the features you chose…',
    why: 'Every app starts from a tested baseline with sign-in, permissions, validation and logging already in place.',
  },
  generate: {
    title: 'Writing your application',
    running: 'Claude is writing the pages, data models and features you described…',
    why: 'The generator works inside strict security rules and can only change files inside your project folder.',
  },
  install: {
    title: 'Installing packages',
    running: 'Downloading the software libraries your app depends on (install scripts are disabled for safety)…',
    why: 'Third-party packages are a common way for attackers to sneak in code, so installation is locked down.',
  },
  typecheck: {
    title: 'Checking the code compiles',
    running: 'Making sure every file is consistent and type-safe…',
    why: 'Type errors often hide real bugs, including security bugs.',
  },
  lint: {
    title: 'Checking coding rules',
    running: 'Running the code-quality and security linters…',
    why: 'Linters catch risky patterns such as unsafe regular expressions and dangerous function calls.',
  },
  'unit-tests': {
    title: 'Running the tests',
    running: 'Running the built-in security tests (sign-in, permissions, headers, forms…) and the app tests…',
    why: 'Tests prove the protections actually work, not just that they exist in the code.',
  },
  sast: {
    title: 'Static security analysis',
    running: 'Reading every source file for known insecure patterns…',
    why: 'This is the same kind of check professional security teams run before release.',
  },
  secrets: {
    title: 'Looking for leaked secrets',
    running: 'Scanning for passwords, API keys and private keys accidentally written into the code…',
    why: 'Secrets in code are one of the most common causes of breaches.',
  },
  deps: {
    title: 'Checking dependencies',
    running: 'Checking every third-party package for known vulnerabilities and producing a bill of materials…',
    why: 'Known vulnerabilities in libraries are exploited within days of disclosure.',
  },
  config: {
    title: 'Checking configuration',
    running: 'Verifying secure settings: environment files, ignored secrets, safe defaults…',
    why: 'Misconfiguration is in the OWASP Top 10 for a reason.',
  },
  dast: {
    title: 'Testing the running app',
    running: 'Starting your app privately on this computer and probing it like an attacker would…',
    why: 'Some problems only show up when the app is actually running.',
  },
  external: {
    title: 'Extra scanners',
    running: 'Running any additional security scanners installed on this computer…',
    why: 'Tools like Semgrep or Trivy add coverage when they are available.',
  },
  'ai-review': {
    title: 'AI security review',
    running: 'Claude is reviewing the code against each applicable OWASP requirement and citing evidence…',
    why: 'Some requirements need judgement, not just pattern matching. Every citation is checked to exist.',
  },
  fix: {
    title: 'Fixing what was found',
    running: 'Claude is fixing the high-priority findings, then the checks run again…',
    why: 'Fixes are recorded in the report so you can see what changed and why.',
  },
  compliance: {
    title: 'Evaluating compliance',
    running: 'Comparing everything that was verified against the OWASP standards…',
    why: 'Each requirement gets a status backed by evidence — or is honestly marked as not verified.',
  },
  reports: {
    title: 'Writing your reports',
    running: 'Producing the compliance report, the security report and the design document…',
    why: 'The reports are written for you, for a developer, and for a security reviewer.',
  },
};

export const StageStatusSchema = z.enum(['pending', 'running', 'passed', 'failed', 'skipped', 'warning']);
export type StageStatus = z.infer<typeof StageStatusSchema>;

export const StageResultSchema = z.object({
  id: StageIdSchema,
  status: StageStatusSchema,
  startedAt: z.string().optional(),
  finishedAt: z.string().optional(),
  durationMs: z.number().optional(),
  summary: z.string().default(''),
  skippedReason: z.string().optional(),
  logFile: z.string().optional(),
  /** Stage-specific structured details (test counts, probe table, …). */
  details: z.unknown().optional(),
  round: z.number().int().default(0),
});
export type StageResult = z.infer<typeof StageResultSchema>;

export const ProgressEventSchema = z.object({
  runId: z.string(),
  type: z.enum(['stage', 'log', 'llm', 'done', 'error', 'heartbeat']),
  stage: StageIdSchema.optional(),
  status: StageStatusSchema.optional(),
  message: z.string(),
  at: z.string(),
  data: z.unknown().optional(),
});
export type ProgressEvent = z.infer<typeof ProgressEventSchema>;

export const LlmUsageSchema = z.object({
  provider: z.string(),
  model: z.string(),
  calls: z.number().int().default(0),
  inputTokens: z.number().int().default(0),
  outputTokens: z.number().int().default(0),
  cacheReadTokens: z.number().int().default(0),
  cacheWriteTokens: z.number().int().default(0),
  estimatedCostUsd: z.number().default(0),
  refusals: z.number().int().default(0),
  fallbacks: z.number().int().default(0),
});
export type LlmUsage = z.infer<typeof LlmUsageSchema>;

export const ToolCoverageSchema = z.object({
  tool: z.string(),
  ran: z.boolean(),
  version: z.string().optional(),
  reason: z.string().optional(),
  /** What the tool covers, in plain language. */
  covers: z.string().optional(),
});
export type ToolCoverage = z.infer<typeof ToolCoverageSchema>;

export const ArtifactRefSchema = z.object({
  name: z.string(), // "compliance-report.html"
  path: z.string(), // relative to the project folder
  kind: z.enum([
    'overview',
    'compliance-report',
    'security-report',
    'design-doc',
    'going-online-checklist',
    'sbom',
    'sarif',
    'provenance',
    'source-zip',
    'run-log',
    'json',
    'other',
  ]),
  format: z.enum(['html', 'md', 'json', 'zip', 'txt', 'sarif']),
  sizeBytes: z.number().int().optional(),
  /** Plain-language description shown on the results page. */
  description: z.string().optional(),
});
export type ArtifactRef = z.infer<typeof ArtifactRefSchema>;

export const RunModeSchema = z.enum(['full', 'demo', 'verify-only']);
export type RunMode = z.infer<typeof RunModeSchema>;

export const GeneratedFileOriginSchema = z.enum(['template', 'expanded', 'ai-generated', 'ai-fixed', 'user']);
export type GeneratedFileOrigin = z.infer<typeof GeneratedFileOriginSchema>;

/**
 * One application of a generation recipe (server/src/generator/recipes): a named, tested way to add one kind of
 * thing to the application. Recorded so a later build, a template upgrade or the version diff can say which
 * recipe produced which files, and so the reports can name the requirements the recipe's own tests speak to.
 */
export const RecipeApplicationSchema = z.object({
  /** Stable recipe id, never reused (e.g. "record-type"). */
  recipeId: z.string(),
  /** Bumped whenever the code a recipe emits changes; a build with an older version can be told apart. */
  recipeVersion: z.string(),
  /** Which thing the recipe built, stable within the project (e.g. the record type's name). */
  instance: z.string(),
  /** Plain-language title of the recipe, for the owner. */
  title: z.string(),
  /** Plain-language description of what this application added, for the owner. */
  description: z.string(),
  /** Paths (relative to the app folder) the recipe wrote. */
  files: z.array(z.string()),
  /**
   * The requirements the recipe's own emitted tests speak to. This is a claim about which test covers what —
   * the evidence is the test result itself, collected by the normal test runner. A recipe that says nothing
   * passes nothing.
   */
  requirements: z.array(
    z.object({
      standard: z.enum(['asvs', 'aisvs']),
      id: z.string(),
      /** The emitted test whose name starts with `id`, so the compliance engine credits it. */
      test: z.string(),
      /** Plain language: what that test actually shows. */
      proves: z.string(),
    }),
  ),
  /** Anything the recipe left out, and why (shown to the owner). */
  notes: z.array(z.string()).default([]),
});
export type RecipeApplication = z.infer<typeof RecipeApplicationSchema>;

/** Written to <app>/securevibe.provenance.json and embedded in every report (AISVS Appendix C AC.7.1 / AC.10.1). */
export const ProvenanceSchema = z.object({
  reportSchemaVersion: z.string(),
  tool: z.string(), // "SecureVibe 0.1.0"
  securevibeVersion: z.string(),
  templateVersion: z.string(),
  frameworkVersions: z.object({ asvs: z.string(), aisvs: z.string(), sbd: z.string() }),
  toolVersions: z.record(z.string(), z.string()), // node, npm, typescript, eslint, external tools
  vulnDbAsOf: z.string().optional(), // when the dependency advisories were last fetched
  runId: z.string(),
  previousRunId: z.string().optional(),
  projectId: z.string(),
  generatedAt: z.string(),
  mode: RunModeSchema,
  llm: z
    .object({
      provider: z.string(),
      requestedModel: z.string(),
      servedModels: z.array(z.string()), // includes fallback models that actually served requests
      promptHashes: z.array(z.string()),
      correlationIds: z.array(z.string()),
      promptLibraryHash: z.string(),
    })
    .optional(),
  humanInvolvement: z.object({
    summary: z.string(), // "Design confirmed and build approved by <owner> in the SecureVibe wizard on <date>"
    buildApprovedAt: z.string().optional(),
    approvedBy: z.string().optional(),
    peerReviewDecisions: z.array(z.object({ suggestionId: z.string(), accepted: z.boolean() })).default([]),
    attestations: z.number().int().default(0),
    humanCodeReview: z.boolean().default(false),
  }),
  designProfileHash: z.string(),
  designHash: z.string(),
  contractHash: z.string().optional(),
  /** sha256 over the sorted list of (path, sha256) of the assessed source tree (excludes node_modules, data). */
  codeTreeHash: z.string(),
  generatedFiles: z.array(
    z.object({
      path: z.string(),
      sha256: z.string(),
      origin: GeneratedFileOriginSchema,
      correlationId: z.string().optional(),
      promptHash: z.string().optional(),
      fixRound: z.number().int().optional(),
      /** Set on files a recipe wrote: which recipe, which version of it, and which thing it was building. */
      recipe: z.object({ id: z.string(), version: z.string(), instance: z.string() }).optional(),
    }),
  ),
  /** sha256 of protected security files captured at scaffold time; re-verified at compliance time. */
  protectedFileHashes: z.record(z.string(), z.string()),
  /** Hash of the template's files at scaffold time: a newer template means an update is available. */
  templateHash: z.string().optional(),
  /** The recipes that were applied to build this app, in the order they ran. */
  recipes: z.array(RecipeApplicationSchema).default([]),
  sandbox: z.object({
    mode: z.string(), // "node-permission-model" | "none"
    note: z.string(), // plain-language limits ("does not restrict network access")
  }),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

export const RunFailureSchema = z.object({
  stage: StageIdSchema.optional(),
  /** Plain-language explanation written for a non-technical reader. */
  message: z.string(),
  /** Technical detail for a developer (log excerpt). */
  detail: z.string().optional(),
  logFile: z.string().optional(),
  /** What the user can do: retry the run, ask Claude to fix (if budget allows), save details for a developer. */
  options: z.array(z.enum(['retry', 'ask-claude-to-fix', 'save-for-developer', 'change-answers', 'add-api-key'])),
});
export type RunFailure = z.infer<typeof RunFailureSchema>;

export const CostEstimateSchema = z.object({
  minutesLow: z.number(),
  minutesHigh: z.number(),
  usdLow: z.number(),
  usdHigh: z.number(),
  spendingCapUsd: z.number(),
  note: z.string(),
});
export type CostEstimate = z.infer<typeof CostEstimateSchema>;

export const PipelineRunSchema = z.object({
  id: z.string(),
  projectId: z.string(),
  mode: RunModeSchema,
  startedAt: z.string(),
  finishedAt: z.string().optional(),
  status: z.enum(['running', 'succeeded', 'failed', 'cancelled', 'interrupted']),
  /** Which stages were requested (verify-only runs skip design-freeze/scaffold/generate). */
  stages: z.array(StageResultSchema),
  findings: z.array(FindingSchema).default([]),
  compliance: ComplianceResultSchema.optional(),
  /**
   * True when the owner asked for only some of the checks (the Security page). Such a run produces no compliance
   * verdict and no reports: the ones on file still come from the last full check, and the page says so.
   */
  partial: z.boolean().optional(),
  /** The checks a partial run was asked for, in the order they ran. */
  partialChecks: z.array(StageIdSchema).optional(),
  coverage: z.array(ToolCoverageSchema).default([]),
  llmUsage: LlmUsageSchema.optional(),
  spendingCapUsd: z.number().optional(),
  artifacts: z.array(ArtifactRefSchema).default([]),
  fixRounds: z.number().int().default(0),
  provenance: ProvenanceSchema.optional(),
  failure: RunFailureSchema.optional(),
  /** Whether the reports were rendered from an incomplete run. */
  incomplete: z.boolean().default(false),
  /**
   * The run this one continued. A build that stopped part-way leaves the code it wrote on disk; continuing keeps
   * that work instead of paying to write it again. The reports say the app was written across both runs.
   */
  resumedFrom: z.string().optional(),
  /** What the earlier run had already done, so the reports can say what was and was not paid for again. */
  resumedNote: z.string().optional(),
  approvedAt: z.string().optional(),
  approvedBy: z.string().optional(),
  /** After the build: each planned feature checked against the pages, records and tests that exist. */
  planCoverage: z
    .array(
      z.object({
        featureId: z.string(),
        title: z.string(),
        status: z.enum(['built', 'partly', 'not-built', 'left-out']),
        /** One plain sentence: what was found and what was not. */
        evidence: z.string(),
      }),
    )
    .optional(),
  /** When the reports were last rewritten with people's answers (without running the checks again). */
  reportsRefreshedAt: z.string().optional(),
  /** What the owner approved on the build page (absent for CLI runs, which record no approval). */
  approval: z
    .object({
      sessionRef: z.string(),
      designHash: z.string(),
      estimateUsdHigh: z.number(),
      estimateShownAt: z.string(),
      spendingCapUsd: z.number(),
    })
    .optional(),
});
export type PipelineRun = z.infer<typeof PipelineRunSchema>;

export const RunSummarySchema = PipelineRunSchema.pick({
  id: true,
  mode: true,
  startedAt: true,
  finishedAt: true,
  status: true,
  partial: true,
}).extend({
  findingCounts: z.record(z.string(), z.number()).optional(),
  complianceRating: z.string().optional(),
});
export type RunSummary = z.infer<typeof RunSummarySchema>;
