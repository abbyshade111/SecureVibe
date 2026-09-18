/**
 * Secure by Design step 5: the AI second opinion on the design.
 *
 * It is labelled honestly (same model, different prompt — DESIGN §13 item 4) and it is fenced: a suggestion that
 * wants to change the profile may only touch a setting from a fixed allow-list, and only in the direction that makes
 * the design stricter. Anything else is recorded as advice for the report and changes nothing.
 */
import type { DesignArtifacts, PeerReview, PeerReviewSuggestion } from '@shared/design.js';
import { DataCategorySchema, type DesignProfile } from '@shared/profile.js';
import { z } from 'zod';
import { peerReviewSystem, wrapUntrusted } from '../prompts/index.js';
import { emptyUsageDelta, type Effort, type LlmProvider, type StructuredFailureReason, type UsageDelta } from '../types.js';
import { renderArchitecture, renderChecklistGaps, renderControls, renderProfile, renderSecurityRequirements } from './context.js';

/** Profile settings a review suggestion may change, and the values it may set them to (strictest direction only). */
export const ALLOWED_PATCH_SETTINGS: Record<string, string[]> = {
  'users.requiresSignIn': ['true'],
  'users.adminMfa': ['true'],
  'users.registration': ['admin-created', 'invite-only'],
  'data.aboutOtherPeople': ['true'],
  'data.retention': ['auto-delete-after-period'],
  'data.categories.add': DataCategorySchema.options as unknown as string[],
  'deployment.businessImpact': ['high'],
  'capabilities.aiAssistant.canTakeActions': ['false'],
  'capabilities.aiAssistant.storesHistory': ['false'],
  'capabilities.aiAssistant.dataItCanSee': ['nothing', 'users-own-records'],
};

export const PeerReviewOutputSchema = z.strictObject({
  summary: z.string().max(2000),
  suggestions: z
    .array(
      z.strictObject({
        kind: z.enum(['control', 'clarification', 'advice']),
        title: z.string().max(140),
        detail: z.string().max(1500),
        severity: z.enum(['high', 'medium', 'low']),
        affectsControls: z.array(z.string().max(40)).max(10),
        /** Empty string unless kind is "clarification". */
        question: z.string().max(300),
        /** Options for a clarification; empty array otherwise. */
        options: z
          .array(z.strictObject({ label: z.string().max(140), setting: z.string().max(80), value: z.string().max(60) }))
          .max(4),
        /** Profile setting to change for a "control" suggestion; empty string when there is nothing to apply. */
        setting: z.string().max(80),
        value: z.string().max(60),
      }),
    )
    .max(8),
});
export type PeerReviewOutput = z.infer<typeof PeerReviewOutputSchema>;

export interface PeerReviewOptions {
  projectId?: string;
  correlationId?: string;
  effort?: Effort;
  now?: Date;
  /** Stops the call (the person chose to skip the second opinion). */
  abort?: AbortSignal;
}

export interface PeerReviewOutcome {
  peerReview: PeerReview;
  usage: UsageDelta;
  failure?: { reason: StructuredFailureReason; message: string };
}

export async function peerReview(
  provider: LlmProvider,
  design: DesignArtifacts,
  profile: DesignProfile,
  opts: PeerReviewOptions = {},
): Promise<PeerReviewOutcome> {
  const now = (opts.now ?? new Date()).toISOString();

  if (provider.name === 'null') {
    return {
      peerReview: {
        performedBy: 'skipped',
        performedAt: now,
        summary: 'The second opinion needs AI, which is not configured. Nothing was reviewed and nothing was changed.',
        suggestions: [],
        skippedReason: 'AI is not configured (preview mode)',
      },
      usage: emptyUsageDelta(provider.model),
    };
  }

  const user = [
    'THE DESIGN TO REVIEW',
    '',
    'What the owner told us:',
    renderProfile(profile),
    '',
    'How the owner described the app (their own words):',
    wrapUntrusted('user-description', profile.app.description, { maxChars: 4000 }),
    '',
    'Plain-language summary of the design:',
    wrapUntrusted('generated-design-summary', design.plainLanguageSummary, { maxChars: 3000 }),
    '',
    renderSecurityRequirements(design),
    '',
    renderArchitecture(design),
    '',
    renderControls(design),
    '',
    renderChecklistGaps(design),
    '',
    'ALLOWED PROFILE SETTINGS for a "control" suggestion (setting = one of these, value = one of its listed values):',
    ...Object.entries(ALLOWED_PATCH_SETTINGS).map(([k, v]) => `  ${k} = ${v.join(' | ')}`),
    '',
    'Leave setting and value empty for "clarification" and "advice" suggestions.',
  ].join('\n');

  const result = await provider.structured({
    purpose: 'peer-review',
    system: peerReviewSystem(),
    user,
    schema: PeerReviewOutputSchema,
    effort: opts.effort ?? 'medium',
    maxTokens: 12_000,
    correlationId: opts.correlationId ?? 'peer-review',
    projectId: opts.projectId ?? 'unknown',
    ...(opts.abort ? { abort: opts.abort } : {}),
  });

  if (!result.ok) {
    return {
      peerReview: {
        performedBy: 'skipped',
        performedAt: now,
        summary: `The second opinion could not be completed. ${result.message}`,
        suggestions: [],
        skippedReason: result.message,
      },
      usage: result.usage,
      failure: { reason: result.reason, message: result.message },
    };
  }

  return {
    peerReview: {
      performedBy: 'claude',
      model: result.servedModel,
      performedAt: now,
      summary: result.data.summary,
      suggestions: toSuggestions(result.data, profile),
    },
    usage: result.usage,
  };
}

/** Turns the model's output into suggestions, downgrading anything that asks for a change we do not allow. */
export function toSuggestions(output: PeerReviewOutput, profile: DesignProfile): PeerReviewSuggestion[] {
  return output.suggestions.map((s, i): PeerReviewSuggestion => {
    const id = `PR-${String(i + 1).padStart(2, '0')}`;
    const base: PeerReviewSuggestion = {
      id,
      kind: s.kind,
      title: s.title,
      detail: s.detail,
      severity: s.severity,
      affectsControls: s.affectsControls,
      accepted: null,
      applied: false,
    };

    if (s.kind === 'clarification') {
      const options = s.options
        .map((o) => ({ label: o.label, patch: patchFor(o.setting, o.value, profile) }))
        .filter((o): o is { label: string; patch: Record<string, unknown> } => o.patch !== undefined)
        .map((o) => ({ label: o.label, profilePatch: o.patch }));
      if (options.length === 0) {
        // No answer SecureVibe could apply: a question the owner cannot answer here would only block the build.
        // Keep it as advice for the reports instead.
        const question = s.question || s.title;
        return { ...base, kind: 'advice', detail: question === s.detail ? s.detail : `${question} ${s.detail}`.trim() };
      }
      return { ...base, question: s.question || s.title, options };
    }

    if (s.kind === 'control') {
      const patch = patchFor(s.setting, s.value, profile);
      if (!patch) {
        // The model asked for something outside the allow-list (or a change that would weaken the design):
        // keep the observation, drop the change.
        return {
          ...base,
          kind: 'advice',
          detail: `${s.detail}\n\n(SecureVibe did not apply a setting change for this suggestion: it is not one of the changes a review may make.)`,
        };
      }
      return { ...base, profilePatch: patch };
    }

    return base;
  });
}

/** Builds a one-setting patch, or undefined when the setting is not allowed or would not make the design stricter. */
export function patchFor(setting: string, value: string, profile: DesignProfile): Record<string, unknown> | undefined {
  const allowed = ALLOWED_PATCH_SETTINGS[setting];
  if (!allowed || !allowed.includes(value)) return undefined;

  if (setting === 'users.registration') {
    const rank: Record<string, number> = { open: 0, 'invite-only': 1, 'admin-created': 2 };
    if ((rank[value] ?? 0) <= (rank[profile.users.registration] ?? 0)) return undefined;
  }
  if (setting === 'capabilities.aiAssistant.dataItCanSee') {
    const rank: Record<string, number> = { 'all-records': 0, 'users-own-records': 1, nothing: 2 };
    if ((rank[value] ?? 0) <= (rank[profile.capabilities.aiAssistant.dataItCanSee] ?? 0)) return undefined;
  }
  if (setting === 'data.categories.add') {
    if (profile.data.categories.includes(value as (typeof profile.data.categories)[number])) return undefined;
  }
  return { [setting]: value === 'true' ? true : value === 'false' ? false : value };
}

/**
 * Applies an accepted suggestion's patch. Kept here so the one place that can change a profile from AI output is the
 * one place that knows the rules. Returns a new profile; unknown settings are ignored.
 */
export function applyPeerReviewPatch(profile: DesignProfile, patch: Record<string, unknown>): DesignProfile {
  const next: DesignProfile = structuredClone(profile);
  for (const [setting, value] of Object.entries(patch)) {
    if (!(setting in ALLOWED_PATCH_SETTINGS)) continue;
    switch (setting) {
      // These three can only be switched on: a patch never turns a protection off.
      case 'users.requiresSignIn':
        if (value === true) next.users.requiresSignIn = true;
        break;
      case 'users.adminMfa':
        if (value === true) next.users.adminMfa = true;
        break;
      case 'users.registration':
        if (value === 'admin-created' || value === 'invite-only') next.users.registration = value;
        break;
      case 'data.aboutOtherPeople':
        if (value === true) next.data.aboutOtherPeople = true;
        break;
      case 'data.retention':
        if (value === 'auto-delete-after-period') {
          next.data.retention = value;
          next.data.retentionMonths = next.data.retentionMonths ?? 24;
        }
        break;
      case 'data.categories.add': {
        const parsed = DataCategorySchema.safeParse(value);
        if (parsed.success && !next.data.categories.includes(parsed.data)) next.data.categories.push(parsed.data);
        break;
      }
      case 'deployment.businessImpact':
        if (value === 'high') next.deployment.businessImpact = 'high';
        break;
      case 'capabilities.aiAssistant.canTakeActions':
        if (value === false) next.capabilities.aiAssistant.canTakeActions = false;
        break;
      case 'capabilities.aiAssistant.storesHistory':
        if (value === false) next.capabilities.aiAssistant.storesHistory = false;
        break;
      case 'capabilities.aiAssistant.dataItCanSee':
        if (value === 'nothing' || value === 'users-own-records') next.capabilities.aiAssistant.dataItCanSee = value;
        break;
      default:
        break;
    }
  }
  return next;
}
