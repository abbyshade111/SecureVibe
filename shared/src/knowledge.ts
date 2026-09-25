/**
 * Knowledge-base shapes stored under data/knowledge and templates/<name>/securevibe.manifest.json.
 * These are data, not code. A build-time test verifies every referenced requirement id exists.
 */
import { z } from 'zod';
import { VerificationClassSchema } from './compliance.js';
import { SbdDomainSchema, SbdPrincipleSchema } from './design.js';
import { SeveritySchema } from './findings.js';

/**
 * Manifest checks. Semantic strength matters: `file-contains` / `file-not-contains` are *negative* checks
 * (they detect a removed or disabled control and can only FAIL a control, never be its sole passing evidence).
 * A control is credited only when all its checks pass AND at least one check is `test`, `dast`, `ast` or `config-value`.
 */
export const ManifestCheckSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('file-exists'), file: z.string() }),
  z.object({ type: z.literal('file-contains'), file: z.string(), pattern: z.string(), flags: z.string().optional() }),
  z.object({ type: z.literal('file-not-contains'), file: z.string(), pattern: z.string(), flags: z.string().optional() }),
  /** Named semantic check implemented in server/src/scanners/ast-checks (e.g. "helmet-registered-with-csp"). */
  z.object({ type: z.literal('ast'), check: z.string(), file: z.string().optional() }),
  /** A node:test test whose full name contains `name` must exist and pass in the generated app. */
  z.object({ type: z.literal('test'), name: z.string() }),
  /** A DAST probe id that must report `passed` (probe declares its own expectation). */
  z.object({ type: z.literal('dast'), probe: z.string() }),
  /** A config check id from server/src/scanners/config. */
  z.object({ type: z.literal('config-value'), key: z.string() }),
  /** No open findings for these rule ids (supporting evidence only). */
  z.object({ type: z.literal('sast-clean'), rules: z.array(z.string()) }),
  /** A generated document must match a regeneration from its source of truth (docs:build). */
  z.object({ type: z.literal('doc-generated'), file: z.string() }),
]);
export type ManifestCheck = z.infer<typeof ManifestCheckSchema>;

export const RequirementMappingSchema = z.object({
  id: z.string(), // "V3.4.3"
  /** One sentence: what passing this control proves about the requirement. Mandatory. */
  proves: z.string(),
  /** Whether this control fully or partly satisfies the requirement. */
  coverage: z.enum(['full', 'partial']).default('full'),
});
export type RequirementMapping = z.infer<typeof RequirementMappingSchema>;

export const TemplateControlSchema = z.object({
  id: z.string(), // TPL-AUTH-01
  title: z.string(),
  description: z.string(), // plain language
  /** Feature toggle that must be on for this control to be expected (omit = always). */
  requiresFeature: z.string().optional(),
  /** Only expected in these TLS modes (omit = all). */
  tlsModes: z.array(z.enum(['off', 'selfsigned', 'proxy'])).optional(),
  asvs: z.array(RequirementMappingSchema).default([]),
  aisvs: z.array(RequirementMappingSchema).default([]),
  sbd: z.array(RequirementMappingSchema).default([]),
  principle: SbdPrincipleSchema.optional(),
  checks: z.array(ManifestCheckSchema).min(1),
  files: z.array(z.string()).default([]),
});
export type TemplateControl = z.infer<typeof TemplateControlSchema>;

export const TemplateManifestSchema = z.object({
  name: z.string(),
  version: z.string(),
  description: z.string(),
  stack: z.array(z.string()),
  engines: z.object({ node: z.string() }),
  features: z.array(
    z.object({
      id: z.string(), // "auth", "uploads", "ai", ...
      description: z.string(),
      /** Files/directories that are removed when the feature is off. */
      paths: z.array(z.string()).default([]),
    }),
  ),
  /** Paths the generation agent may never write or delete (enforced by the tool layer, hashed at scaffold). */
  protectedPaths: z.array(z.string()),
  /** Paths the agent may create/modify/delete (globs). */
  writablePaths: z.array(z.string()),
  /** Packages that may be imported by generated code (package.json is not editable by the agent). */
  allowedImports: z.array(z.string()),
  controls: z.array(TemplateControlSchema),
  /** Conventions the generator must follow (shown to Claude as the template API reference). */
  conventions: z.array(z.string()).default([]),
  /** Test-bootstrap contract used by the DAST harness (env var names, ready line, routes export path). */
  testMode: z.object({
    envFlag: z.string(), // "SECUREVIBE_TEST_MODE"
    readyLinePrefix: z.string(), // '{"securevibe":"listening"'
    routesEndpoint: z.string(), // "/__securevibe/routes"
    seededUsers: z.array(z.object({ role: z.string(), email: z.string(), passwordEnv: z.string() })),
  }),
});
export type TemplateManifest = z.infer<typeof TemplateManifestSchema>;

/** data/knowledge/patterns.json */
export const PatternCatalogEntrySchema = z.object({
  id: z.string(),
  name: z.string(),
  principle: SbdPrincipleSchema,
  sbdDomain: SbdDomainSchema,
  description: z.string(),
  whyTemplate: z.string(), // "{appName} …" plain-language sentence template
  implementedBy: z.array(z.string()).default([]),
  sbdChecklist: z.array(z.string()).default([]),
  asvs: z.array(z.string()).default([]),
  aisvs: z.array(z.string()).default([]),
  when: z.enum([
    'always',
    'auth',
    'sensitive-data',
    'personal-data',
    'uploads',
    'ai',
    'ai-actions',
    'email',
    'external-apis',
    'public-api',
    'payments',
    'internet',
    'lan',
    'scheduler',
    'level2',
  ]),
});
export type PatternCatalogEntry = z.infer<typeof PatternCatalogEntrySchema>;

/** data/knowledge/remediation.json — rule id → guidance */
export const RemediationEntrySchema = z.object({
  ruleId: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  cwe: z.array(z.string()).default([]),
  description: z.string(),
  impact: z.string(),
  remediation: z.object({
    summary: z.string(),
    steps: z.array(z.string()),
    example: z.string().optional(),
    references: z.array(z.string()).default([]),
  }),
  howToConfirmFixed: z.string().optional(),
  asvs: z.array(z.string()).default([]),
  aisvs: z.array(z.string()).default([]),
  sbd: z.array(z.string()).default([]),
  exploitability: z.enum(['trivial', 'requires-auth', 'requires-network-exposure', 'theoretical']).optional(),
});
export type RemediationEntry = z.infer<typeof RemediationEntrySchema>;

/** data/knowledge/requirements-plain.json — requirement id → plain-language explanation + manual verification */
export const RequirementPlainSchema = z.object({
  id: z.string(),
  plain: z.string(),
  manual: z
    .object({
      whoCanDo: z.enum(['owner', 'developer', 'security-professional', 'hosting-provider']),
      question: z.string().optional(),
      steps: z.array(z.string()).default([]),
      whatCountsAsEvidence: z.string().optional(),
      estimatedEffort: z.enum(['minutes', 'hour', 'day']).default('minutes'),
    })
    .optional(),
});
export type RequirementPlain = z.infer<typeof RequirementPlainSchema>;

/** data/knowledge/applicability.json — per-section/per-requirement applicability and verification class. */
export const ApplicabilityConditionSchema = z.enum([
  'always',
  'never',
  'auth',
  'no-auth',
  'uploads',
  'ai',
  'ai-actions',
  'ai-history',
  'ai-moderation',
  'email',
  'external-apis',
  'public-api',
  'payments',
  'scheduler',
  'tls',
  'internet',
  'level2',
  'oauth',
  'authorization-server',
  'webrtc',
  'jwt',
  'rag',
  'mcp',
  'multi-tenant',
  'training',
  'self-assessment',
]);
export type ApplicabilityCondition = z.infer<typeof ApplicabilityConditionSchema>;

export const ApplicabilityRuleSchema = z.object({
  /** Requirement id, section id (e.g. "V10.1", "C9.2") or chapter id ("V17", "C1"). Most specific wins. */
  scope: z.string(),
  condition: ApplicabilityConditionSchema,
  /** Fixed reason shown when the condition makes the scope not applicable. */
  notApplicableReason: z.string().optional(),
  verificationClass: VerificationClassSchema.optional(),
  /** Deployment-time note for requirements that only make sense once deployed. */
  deploymentNote: z.string().optional(),
});
export type ApplicabilityRule = z.infer<typeof ApplicabilityRuleSchema>;

export const ApplicabilityConfigSchema = z.object({
  rules: z.array(ApplicabilityRuleSchema),
  /** Requirement ids that can never be `pass` (test-enforced). */
  manualOnly: z.array(z.string()),
  /** Default verification class when no rule states one. */
  defaultVerificationClass: VerificationClassSchema,
});
export type ApplicabilityConfig = z.infer<typeof ApplicabilityConfigSchema>;

/** data/knowledge/sbd-rules.json — how each SbD checklist control is answered from the profile. */
export const SbdRuleSchema = z.object({
  id: z.string(), // AS-01
  severityIfNo: z.enum(['high', 'medium', 'low']),
  /** Ordered: first matching condition wins. */
  outcomes: z.array(
    z.object({
      when: z.enum([
        'always',
        'local-only',
        'local-network',
        'internet-later',
        'auth',
        'no-auth',
        'no-central-sign-in',
        'sensitive-data',
        'personal-data',
        'ai',
        'external-apis',
        'email',
        'scheduler',
        'uploads',
        'attested', // the owner attested (e.g. rehearsed the incident plan)
      ]),
      status: z.enum(['yes', 'no', 'n-a']),
      justification: z.string(),
      evidence: z.array(z.string()).default([]),
      actions: z.array(z.object({ text: z.string(), owner: z.string(), dueBy: z.string().optional() })).default([]),
      deploymentNote: z.string().optional(),
      /** Re-evaluated status under an internet deployment assumption. */
      deploymentTimeStatus: z.enum(['yes', 'no', 'n-a', 'deferred']).optional(),
      note: z.string().optional(),
    }),
  ),
});
export type SbdRule = z.infer<typeof SbdRuleSchema>;
