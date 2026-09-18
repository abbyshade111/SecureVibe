/**
 * Applicability engine (CONTRACTS §8): which ASVS / AISVS / Appendix C requirements apply to a design.
 *
 * Rules live in data/knowledge/applicability.json. Resolution for a requirement id:
 *   1. the target level comes from targetLevel() (shared/src/profile.ts); requirements above it are out-of-level;
 *   2. the most specific rule scope wins: requirement id > section id > chapter id;
 *   3. several rules with the same scope are OR-ed (the scope applies when any of their conditions holds) —
 *      this is how "V12.3 applies with external APIs, AI or email" is expressed with a single-condition schema;
 *   4. no rule at all means the requirement applies.
 */
import type { VerificationClass } from '@shared/compliance.js';
import type { Applicability, BuildSpec } from '@shared/design.js';
import type { ApplicabilityCondition, ApplicabilityRule, PatternCatalogEntry } from '@shared/knowledge.js';
import {
  profileHasPersonalData,
  profileHasSensitiveData,
  targetLevel,
  type DesignProfile,
} from '@shared/profile.js';
import { loadKnowledge, type Knowledge } from './knowledge.js';
import { chapterIdOf, loadFrameworks, sectionIdOf, type Frameworks, type RequirementInfo } from './load.js';

export interface ApplicabilityOptions {
  /** SecureVibe assessing itself: AISVS is evaluated and the agent counts as an AI that takes actions. */
  selfAssessment?: boolean;
  /** An app the owner uploaded: Appendix C (AI-assisted development) applies only when AI tools helped write it. */
  uploaded?: { aiAssisted: boolean };
}

export type ConditionContext = Record<ApplicabilityCondition, boolean>;

/** Plain-language reason used when a rule gives none. */
export const DEFAULT_NOT_APPLICABLE_REASONS: Record<ApplicabilityCondition, string> = {
  always: 'This requirement always applies.',
  never: 'This requirement covers a technology or setup this app does not use.',
  auth: 'This app has no sign-in, so there are no accounts, passwords or sessions to protect.',
  'no-auth': 'This app has sign-in, so this requirement for apps without accounts does not apply.',
  uploads: 'This app does not accept file uploads.',
  ai: 'This app has no AI assistant.',
  'ai-actions': 'The AI assistant can only answer questions; it cannot change data or take actions.',
  'ai-history': 'The AI assistant does not keep conversation history between visits.',
  'ai-moderation': 'Content moderation is not turned on for the AI assistant.',
  email: 'This app does not send email.',
  'external-apis': 'This app does not call other services over the network.',
  'public-api': 'This app does not offer API keys for other programs to connect.',
  payments: 'This app does not take payments.',
  scheduler: 'This app has no scheduled background jobs.',
  tls: 'This app runs on this computer only, without HTTPS, so there is no network connection to encrypt.',
  internet: 'This app is not intended to go on the internet.',
  level2: 'This only applies at level 2, and this app targets level 1.',
  oauth: 'This app uses its own local accounts, not sign-in through another provider (OAuth or OpenID Connect).',
  webrtc: 'This app has no real-time audio or video calls (WebRTC).',
  jwt: 'This app does not issue self-contained tokens such as JWTs; its API keys are opaque values checked against the database.',
  rag: 'The AI assistant does not search a document store or vector database (no retrieval-augmented generation).',
  mcp: 'The AI assistant does not use the Model Context Protocol (MCP) to talk to tools.',
  'multi-tenant': 'This app serves one organisation, not several separate customer organisations sharing one system.',
  training: 'This app does not train or fine-tune any AI model; it uses a ready-made model from a vendor.',
  'self-assessment': 'This is only evaluated when SecureVibe assesses itself.',
};

export function buildConditionContext(
  profile: DesignProfile,
  buildSpec: BuildSpec,
  opts: ApplicabilityOptions = {},
): ConditionContext {
  const f = buildSpec.features;
  const selfAssessment = opts.selfAssessment === true;
  const ai = f.ai || selfAssessment;
  return {
    always: true,
    never: false,
    auth: f.auth,
    'no-auth': !f.auth,
    uploads: f.uploads,
    ai,
    // SecureVibe's own generation agent writes files, so it counts as an AI that takes actions.
    'ai-actions': (f.aiActions && ai) || selfAssessment,
    'ai-history': ai && profile.capabilities.aiAssistant.storesHistory,
    'ai-moderation': ai && f.aiModeration,
    email: f.email,
    'external-apis': profile.capabilities.externalApis.length > 0,
    'public-api': f.publicApi,
    payments: f.payments,
    scheduler: f.scheduler,
    tls: f.tlsMode !== 'off',
    internet: profile.deployment.target === 'internet-later',
    level2: targetLevel(profile).level === 2,
    oauth: false,
    webrtc: false,
    jwt: false,
    rag: false,
    mcp: false,
    'multi-tenant': false,
    training: false,
    'self-assessment': selfAssessment,
  };
}

export function conditionHolds(condition: ApplicabilityCondition, ctx: ConditionContext): boolean {
  return ctx[condition];
}

/** The rules at the most specific scope covering `id` (requirement > section > chapter); empty when none. */
export function rulesFor(id: string, rules: ApplicabilityRule[]): ApplicabilityRule[] {
  const candidates = [id, sectionIdOf(id), chapterIdOf(id)];
  for (const scope of candidates) {
    const matching = rules.filter((r) => r.scope === scope);
    if (matching.length > 0) return matching;
  }
  return [];
}

function knowledgeOrDefault(knowledge?: Knowledge): Knowledge {
  return knowledge ?? loadKnowledge();
}

export function isManualOnly(id: string, knowledge?: Knowledge): boolean {
  return knowledgeOrDefault(knowledge).applicability.manualOnly.includes(id);
}

/** Verification class: manual-only list first, then the most specific rule that states one, then the default. */
export function verificationClassFor(id: string, knowledge?: Knowledge): VerificationClass {
  const k = knowledgeOrDefault(knowledge);
  if (k.applicability.manualOnly.includes(id)) return 'manual-only';
  const stated = rulesFor(id, k.applicability.rules).find((r) => r.verificationClass);
  return stated?.verificationClass ?? k.applicability.defaultVerificationClass;
}

/** Deployment-time note from the most specific rule for `id`, if any. */
export function deploymentNoteFor(id: string, knowledge?: Knowledge): string | undefined {
  const k = knowledgeOrDefault(knowledge);
  return rulesFor(id, k.applicability.rules).find((r) => r.deploymentNote)?.deploymentNote;
}

interface Bucketed {
  applicable: string[];
  notApplicable: { id: string; reason: string }[];
  outOfLevel: string[];
}

function bucket(requirements: RequirementInfo[], rules: ApplicabilityRule[], ctx: ConditionContext, level: 1 | 2): Bucketed {
  const out: Bucketed = { applicable: [], notApplicable: [], outOfLevel: [] };
  for (const r of requirements) {
    if (r.level > level) {
      out.outOfLevel.push(r.id);
      continue;
    }
    const matching = rulesFor(r.id, rules);
    if (matching.length === 0 || matching.some((rule) => conditionHolds(rule.condition, ctx))) {
      out.applicable.push(r.id);
      continue;
    }
    const first = matching[0]!;
    out.notApplicable.push({
      id: r.id,
      reason: first.notApplicableReason ?? DEFAULT_NOT_APPLICABLE_REASONS[first.condition],
    });
  }
  return out;
}

export function computeApplicability(
  profile: DesignProfile,
  buildSpec: BuildSpec,
  knowledge: Knowledge = loadKnowledge(),
  frameworks: Frameworks = loadFrameworks(),
  opts: ApplicabilityOptions = {},
): Applicability {
  const { level, rule } = targetLevel(profile);
  const ctx = buildConditionContext(profile, buildSpec, opts);
  const rules = knowledge.applicability.rules;

  const asvs = bucket(frameworks.listRequirements('asvs'), rules, ctx, level);
  const appendixC =
    opts.uploaded && !opts.uploaded.aiAssisted
      ? {
          applicable: [],
          notApplicable: frameworks
            .listRequirements('aisvs-appendix-c')
            .filter((r) => r.level <= level)
            .map((r) => ({ id: r.id, reason: 'You said this app was written without AI tools, so the rules for AI-assisted development do not apply.' })),
          outOfLevel: frameworks.listRequirements('aisvs-appendix-c').filter((r) => r.level > level).map((r) => r.id),
        }
      : bucket(frameworks.listRequirements('aisvs-appendix-c'), rules, ctx, level);

  const aisvsEnabled = ctx.ai;
  let aisvsReason: string;
  if (opts.selfAssessment) {
    aisvsReason =
      'Evaluated because SecureVibe itself uses an AI model to design and generate code, and its generation agent writes files (counted as taking actions).';
  } else if (buildSpec.features.ai) {
    aisvsReason = 'Evaluated because this app includes an AI assistant that accepts text from users and calls an AI model.';
  } else {
    aisvsReason =
      'Not evaluated: this app has no AI assistant, so the AI security standard (OWASP AISVS) does not apply to it. The build process is still checked against AISVS Appendix C.';
  }
  const aisvs = aisvsEnabled
    ? bucket(frameworks.listRequirements('aisvs'), rules, ctx, level)
    : { applicable: [], notApplicable: [], outOfLevel: [] };

  return {
    targetLevel: level,
    targetLevelRule: rule,
    asvs,
    aisvs: { enabled: aisvsEnabled, reason: aisvsReason, ...aisvs },
    appendixC,
  };
}

/**
 * Whether a pattern from data/knowledge/patterns.json is selected for a design.
 * For patterns, 'external-apis' means any outbound connection (external APIs, the AI provider or a mail server),
 * so the egress allow-list pattern is selected whenever the app talks to another service.
 */
export function patternApplies(
  entry: Pick<PatternCatalogEntry, 'when'>,
  profile: DesignProfile,
  buildSpec: BuildSpec,
  opts: ApplicabilityOptions = {},
): boolean {
  const ctx = buildConditionContext(profile, buildSpec, opts);
  switch (entry.when) {
    case 'always':
      return true;
    case 'sensitive-data':
      return profileHasSensitiveData(profile);
    case 'personal-data':
      return profileHasPersonalData(profile);
    case 'external-apis':
      return ctx['external-apis'] || ctx.ai || ctx.email;
    case 'internet':
      return ctx.internet;
    case 'lan':
      return profile.deployment.target === 'local-network';
    default:
      return ctx[entry.when];
  }
}
