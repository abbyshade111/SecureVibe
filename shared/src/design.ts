/**
 * Design artifacts produced by the SbD engine (SbD steps 2-8) from a DesignProfile.
 */
import { z } from 'zod';
import { DataCategorySchema } from './profile.js';

export const SbdPrincipleSchema = z.enum([
  'least-privilege',
  'defense-in-depth',
  'secure-defaults',
  'zero-trust-explicit-boundaries',
  'fail-secure-graceful-degradation',
  'simplicity-minimized-attack-surface',
  'observability-by-design',
  'contract-first-versioned-interfaces',
  'automation-repeatability',
]);
export type SbdPrinciple = z.infer<typeof SbdPrincipleSchema>;

export const SbdDomainSchema = z.enum(['A', 'B', 'C', 'D', 'E']); // checklist domains A..E
export type SbdDomain = z.infer<typeof SbdDomainSchema>;

export const SecurityRequirementSchema = z.object({
  id: z.string(), // SR-01
  statement: z.string(), // plain language: "Only signed-in staff can see customer records"
  category: z.enum(['confidentiality', 'integrity', 'availability', 'privacy', 'compliance', 'accountability']),
  drivenBy: z.array(z.string()), // profile paths, e.g. "users.requiresSignIn"
  asvs: z.array(z.string()).default([]),
  aisvs: z.array(z.string()).default([]),
  sbd: z.array(z.string()).default([]), // checklist ids
});
export type SecurityRequirement = z.infer<typeof SecurityRequirementSchema>;

export const TrustZoneSchema = z.object({
  id: z.string(), // "browser", "app", "data", "vendor"
  name: z.string(),
  level: z.enum(['untrusted', 'semi-trusted', 'trusted']),
  description: z.string(),
});
export type TrustZone = z.infer<typeof TrustZoneSchema>;

export const ComponentSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum([
    'browser',
    'web-app',
    'database',
    'file-storage',
    'ai-provider',
    'email-service',
    'external-api',
    'scheduler',
    'payment-provider',
    'api-client',
  ]),
  trustZone: z.string(),
  description: z.string(),
});
export type Component = z.infer<typeof ComponentSchema>;

export const DataFlowSchema = z.object({
  id: z.string(),
  from: z.string(), // component id
  to: z.string(),
  description: z.string(),
  data: z.array(z.union([DataCategorySchema, z.string()])).default([]),
  protocol: z.string(), // "HTTPS", "HTTP (localhost)", "SQLite file", "HTTPS (vendor API)"
  crossesTrustBoundary: z.boolean(),
  controls: z.array(z.string()).default([]), // template control ids / pattern ids
});
export type DataFlow = z.infer<typeof DataFlowSchema>;

export const ExternalDependencySchema = z.object({
  name: z.string(),
  purpose: z.string(),
  trust: z.enum(['vendor', 'untrusted', 'platform']),
  dataShared: z.array(z.string()).default([]),
  mitigations: z.array(z.string()).default([]),
});
export type ExternalDependency = z.infer<typeof ExternalDependencySchema>;

export const ArchitectureSchema = z.object({
  components: z.array(ComponentSchema),
  trustZones: z.array(TrustZoneSchema),
  dataFlows: z.array(DataFlowSchema),
  externalDependencies: z.array(ExternalDependencySchema),
  /** Explicit design assumptions (SbD step 2), e.g. "runs on one computer; the owner is the only administrator". */
  assumptions: z.array(z.string()).default([]),
  /** Mermaid diagram source (flowchart) with trust zones as subgraphs and control ids on edges. */
  mermaid: z.string(),
  plainLanguage: z.string(), // walkthrough for non-experts
});
export type Architecture = z.infer<typeof ArchitectureSchema>;

export const PatternSchema = z.object({
  id: z.string(), // "PAT-RBAC"
  name: z.string(),
  principle: SbdPrincipleSchema,
  sbdDomain: SbdDomainSchema,
  why: z.string(), // one sentence, plain language, referencing the user's answers
  appliesTo: z.array(z.string()).default([]), // component / flow ids
  implementedBy: z.array(z.string()).default([]), // template control ids (TPL-*)
  sbdChecklist: z.array(z.string()).default([]), // checklist ids satisfied/supported
});
export type Pattern = z.infer<typeof PatternSchema>;

export const SbdChecklistStatusSchema = z.enum(['yes', 'no', 'n-a']);
export type SbdChecklistStatus = z.infer<typeof SbdChecklistStatusSchema>;

export const SbdActionSchema = z.object({
  text: z.string(),
  owner: z.string(), // "owner:<name>" | "developer" | "hosting-provider"
  dueBy: z.string().optional(), // "before internet deployment" or an ISO date
});

export const SbdChecklistEntrySchema = z.object({
  id: z.string(), // AS-01
  domain: SbdDomainSchema,
  statement: z.string(),
  critical: z.boolean(),
  status: SbdChecklistStatusSchema,
  justification: z.string(),
  /** Severity if the control is not implemented (from the framework's row format); fixed defaults per control. */
  severityIfNo: z.enum(['high', 'medium', 'low']),
  /** Score contribution: yes=0, n-a=0, no(low)=1, no(medium)=2, no(high)=4. */
  score: z.number().int().default(0),
  evidence: z.array(z.string()).default([]), // pointers: "template:TPL-HEADERS-01", "design:PAT-RBAC", "doc:docs/incident-response.md"
  /** Required (>= 1) whenever status is "no" (SbD step 5: unresolved No items become actions). */
  actions: z.array(SbdActionSchema).default([]),
  /** Time-bound mitigation plan, required for a critical control answered "no". */
  mitigationPlan: z.object({ owner: z.string(), dueBy: z.string(), action: z.string() }).optional(),
  /** What changes when the app is exposed to a network / the internet. */
  deploymentNote: z.string().optional(),
  comment: z.string().optional(),
  adrIds: z.array(z.string()).default([]),
  /** Plain-language note for the user ("What this means for you"). */
  note: z.string().optional(),
});
export type SbdChecklistEntry = z.infer<typeof SbdChecklistEntrySchema>;

export const PeerReviewSuggestionSchema = z.object({
  id: z.string(),
  /** "control": a security control suggestion (applied automatically, shown as "We also added…");
   *  "clarification": a plain-language business question the user answers;
   *  "advice": a recommendation recorded for the report only. */
  kind: z.enum(['control', 'clarification', 'advice']),
  title: z.string(),
  detail: z.string(),
  severity: z.enum(['high', 'medium', 'low']),
  affectsControls: z.array(z.string()).default([]),
  /** For clarifications: the question and the options shown to the user. */
  question: z.string().optional(),
  options: z
    .array(z.object({ label: z.string(), profilePatch: z.record(z.string(), z.unknown()) }))
    .optional(),
  /** Machine-applicable profile change, when the suggestion can be applied automatically. */
  profilePatch: z.record(z.string(), z.unknown()).optional(),
  /** null = pending; true = applied/accepted; false = dismissed (reason recorded). */
  accepted: z.boolean().nullable().default(null),
  dismissReason: z.string().optional(),
  applied: z.boolean().default(false),
});
export type PeerReviewSuggestion = z.infer<typeof PeerReviewSuggestionSchema>;

export const PeerReviewSchema = z.object({
  performedBy: z.enum(['claude', 'rules', 'skipped']),
  model: z.string().optional(),
  performedAt: z.string(),
  summary: z.string(),
  suggestions: z.array(PeerReviewSuggestionSchema).default([]),
  skippedReason: z.string().optional(),
});
export type PeerReview = z.infer<typeof PeerReviewSchema>;

export const EscalationTriggerSchema = z.object({
  id: z.enum(['sensitive-data', 'external-exposure', 'novel-technology', 'tier-1-impact']),
  name: z.string(),
  triggered: z.boolean(),
  reason: z.string(),
});
export type EscalationTrigger = z.infer<typeof EscalationTriggerSchema>;

export const RiskTriageSchema = z.object({
  /** SbD scoring: Yes=0, N-A=0 (with justification), No(Low)=1, No(Med)=2, No(High)=4 */
  score: z.number(),
  threshold: z.number().default(6),
  notApplicableCount: z.number().int().default(0),
  criticalNo: z.array(z.string()).default([]),
  triggers: z.array(EscalationTriggerSchema),
  level: z.enum(['low', 'normal', 'high']),
  /** Escalate when: any critical = No, or score >= threshold, or any trigger applies (exactly as the framework states). */
  escalate: z.boolean(),
  escalationReasons: z.array(z.string()).default([]),
  /** How the escalation is satisfied when no AppSec team exists (threat model + owner acknowledgment). */
  escalationHandling: z.string(),
  threatModelRequired: z.boolean(),
  /** User-facing label: "Standard care" / "Extra care" — always paired with what was done. */
  extraCareLabel: z.string(),
  plainLanguage: z.string(),
});
export type RiskTriage = z.infer<typeof RiskTriageSchema>;

export const StrideCategorySchema = z.enum([
  'spoofing',
  'tampering',
  'repudiation',
  'information-disclosure',
  'denial-of-service',
  'elevation-of-privilege',
]);
export type StrideCategory = z.infer<typeof StrideCategorySchema>;

export const ThreatSchema = z.object({
  id: z.string(), // T-01
  stride: StrideCategorySchema,
  target: z.string(), // component or data-flow id
  description: z.string(),
  likelihood: z.enum(['low', 'medium', 'high']),
  impact: z.enum(['low', 'medium', 'high']),
  riskLevel: z.enum(['low', 'medium', 'high']),
  mitigations: z.array(
    z.object({
      control: z.string(), // template control id / pattern id
      description: z.string(),
      requirementIds: z.array(z.string()).default([]), // ASVS/AISVS ids that verify the mitigation
    }),
  ),
  residualRisk: z.enum(['low', 'medium', 'high']),
  status: z.enum(['mitigated', 'accepted', 'open']),
  actionItems: z.array(z.string()).default([]),
});
export type Threat = z.infer<typeof ThreatSchema>;

/** The threats array doubles as the prioritized risk register (sorted by riskLevel). */
export const ThreatModelSchema = z.object({
  method: z.literal('STRIDE'),
  performedBy: z.enum(['claude', 'rules']),
  model: z.string().optional(),
  performedAt: z.string(),
  scope: z.string(),
  assets: z.array(z.string()),
  entryPoints: z.array(z.string()),
  trustBoundaries: z.array(z.string()),
  threats: z.array(ThreatSchema),
  summary: z.string(),
});
export type ThreatModel = z.infer<typeof ThreatModelSchema>;

export const AdrSchema = z.object({
  id: z.string(), // ADR-001
  title: z.string(),
  status: z.enum(['accepted']),
  date: z.string(),
  context: z.string(),
  decision: z.string(),
  alternatives: z.array(z.string()).default([]),
  consequences: z.string(),
  relatedControls: z.array(z.string()).default([]),
  relatedRequirements: z.array(z.string()).default([]),
});
export type Adr = z.infer<typeof AdrSchema>;

export const SecurityContractRuleSchema = z.object({
  id: z.string(), // SC-01
  rule: z.string(), // imperative rule for the code generator
  rationale: z.string(),
  asvs: z.array(z.string()).default([]),
  aisvs: z.array(z.string()).default([]),
  enforcedBy: z.array(z.enum(['template', 'sast', 'lint', 'dast', 'tests', 'ai-review', 'config'])).default([]),
});
export type SecurityContractRule = z.infer<typeof SecurityContractRuleSchema>;

export const SecurityContractSchema = z.object({
  version: z.string(),
  rules: z.array(SecurityContractRuleSchema),
});
export type SecurityContract = z.infer<typeof SecurityContractSchema>;

export const NotApplicableSchema = z.object({ id: z.string(), reason: z.string() });

export const ApplicabilitySchema = z.object({
  /** Single target level used by ASVS and AISVS alike (AISVS level N assumes ASVS level N). */
  targetLevel: z.union([z.literal(1), z.literal(2)]),
  targetLevelRule: z.string(), // plain-language reason
  asvs: z.object({
    applicable: z.array(z.string()),
    notApplicable: z.array(NotApplicableSchema),
    outOfLevel: z.array(z.string()),
  }),
  aisvs: z.object({
    enabled: z.boolean(),
    reason: z.string(),
    applicable: z.array(z.string()),
    notApplicable: z.array(NotApplicableSchema),
    outOfLevel: z.array(z.string()),
  }),
  /** AISVS Appendix C (AI-assisted secure coding) applied to the build process that produced the app. */
  appendixC: z.object({
    applicable: z.array(z.string()),
    notApplicable: z.array(NotApplicableSchema),
    outOfLevel: z.array(z.string()),
  }),
});
export type Applicability = z.infer<typeof ApplicabilitySchema>;

/** Feature toggles + generation brief derived from the profile for the template scaffolder and the generator. */
export const BuildSpecSchema = z.object({
  features: z.object({
    auth: z.boolean(),
    adminMfa: z.boolean(),
    /** TOTP available to every user (always true at target level 2). */
    userMfa: z.boolean(),
    uploads: z.boolean(),
    ai: z.boolean(),
    aiActions: z.boolean(),
    /** Older saved designs predate this answer, so it defaults to off. */
    aiWebSearch: z.boolean().default(false),
    aiModeration: z.boolean(),
    email: z.boolean(),
    scheduler: z.boolean(),
    publicApi: z.boolean(),
    payments: z.boolean(),
    fieldEncryption: z.boolean(),
    retentionJobs: z.boolean(),
    lanBinding: z.boolean(),
    /** "off" for local-only (plain HTTP on loopback), "proxy" for internet-later (behind a TLS proxy), "selfsigned" for LAN. */
    tlsMode: z.enum(['off', 'selfsigned', 'proxy']),
  }),
  /** Package name safe identifier derived from app name. */
  packageName: z.string(),
  /** Session policy constants written into the generated app's config. */
  sessionPolicy: z.object({ idleMinutes: z.number(), absoluteHours: z.number(), maxConcurrent: z.number() }),
  /** The generation brief handed to Claude (plain text, deterministic from the design). */
  brief: z.string(),
});
export type BuildSpec = z.infer<typeof BuildSpecSchema>;

export const DesignArtifactsSchema = z.object({
  generatedAt: z.string(),
  profileHash: z.string(),
  securityRequirements: z.array(SecurityRequirementSchema),
  architecture: ArchitectureSchema,
  patterns: z.array(PatternSchema),
  checklist: z.array(SbdChecklistEntrySchema),
  peerReview: PeerReviewSchema.optional(),
  riskTriage: RiskTriageSchema,
  threatModel: ThreatModelSchema.optional(),
  adrs: z.array(AdrSchema),
  securityContract: SecurityContractSchema,
  applicability: ApplicabilitySchema,
  buildSpec: BuildSpecSchema,
  /** "Here is what we will build" — 3-6 sentences plus one bullet per consequence, grade-8 reading level. */
  plainLanguageSummary: z.string(),
  consequences: z.array(z.string()),
  /** Assumptions made on the user's behalf ("Not sure" answers, quick-mode inferences) that the summary shows. */
  assumptionsMade: z.array(z.string()).default([]),
  /** Plain-language "What this changes" statements shown in the wizard, keyed by profile area. */
  whatThisChanges: z.record(z.string(), z.array(z.string())),
  /** sha256 of the security contract + prompt library at design-freeze (verified on every load). */
  contractHash: z.string().optional(),
});
export type DesignArtifacts = z.infer<typeof DesignArtifactsSchema>;
