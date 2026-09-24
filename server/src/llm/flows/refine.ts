/**
 * "Let's check a few things": after the owner has described their app and answered the questions, Claude reads the
 * answers and comes back with
 *   - follow-up questions, only where an answer is genuinely missing or could mean two different things, and
 *   - features it thinks the app needs to do what was described.
 *
 * Nothing here changes the design by itself. Each question offers plain answers, and each suggested feature is a
 * proposal the owner accepts or declines; only then does SecureVibe write it into the answers. A suggestion may
 * only touch the answers from a fixed allow-list, in the same spirit as the second opinion.
 */
import { z } from 'zod';
import type { PartialDesignProfile } from '@shared/profile.js';
import type { Refinement, RefinementQuestion, RefinementSuggestion } from '@shared/project.js';
import { refineSystem, wrapUntrusted } from '../prompts/index.js';
import { emptyUsageDelta, type Effort, type LlmProvider, type StructuredFailureReason, type UsageDelta } from '../types.js';
import { renderPartialProfile } from './context.js';

/**
 * Answers a follow-up question may set, and the values allowed. Free-text answers are only ever added to the
 * feature list or the record list, never to a security setting.
 */
export const REFINE_ANSWER_FIELDS: Record<string, string[] | 'text'> = {
  'app.description': 'text',
  'app.keyFeatures.add': 'text',
  'app.entities.add': 'text',
  'users.audience': ['just-me', 'my-team', 'customers', 'public'],
  'users.requiresSignIn': ['true', 'false'],
  'data.aboutOtherPeople': ['true', 'false'],
  'data.retention': ['keep-until-deleted', 'auto-delete-after-period'],
  'capabilities.fileUploads': ['true', 'false'],
  'capabilities.email': ['true', 'false'],
  'capabilities.scheduledJobs': ['true', 'false'],
  'capabilities.publicApi': ['true', 'false'],
  'capabilities.payments': ['true', 'false'],
  'capabilities.aiAssistant.enabled': ['true', 'false'],
  'capabilities.aiAssistant.canSearchWeb': ['true', 'false'],
  'capabilities.aiAssistant.storesHistory': ['true', 'false'],
};

export const RefineOutputSchema = z.strictObject({
  summary: z.string().max(1200),
  questions: z
    .array(
      z.strictObject({
        question: z.string().max(300),
        why: z.string().max(400),
        /** The answer this question sets; empty when it is only for the owner to think about. */
        field: z.string().max(80),
        options: z.array(z.strictObject({ label: z.string().max(140), value: z.string().max(200) })).max(4),
      }),
    )
    .max(6),
  features: z
    .array(
      z.strictObject({
        title: z.string().max(140),
        detail: z.string().max(600),
        /** "app.keyFeatures.add", "app.entities.add" or a capability from the allow-list. */
        field: z.string().max(80),
        value: z.string().max(200),
      }),
    )
    .max(8),
});
export type RefineOutput = z.infer<typeof RefineOutputSchema>;

export interface RefineOptions {
  projectId?: string;
  correlationId?: string;
  effort?: Effort;
  now?: Date;
  abort?: AbortSignal;
}

export interface RefineOutcome {
  refinement: Refinement;
  usage: UsageDelta;
  failure?: { reason: StructuredFailureReason; message: string };
}

/** True when a suggested change is one SecureVibe will let the owner accept. */
export function answerFieldAllowed(field: string, value: string): boolean {
  const allowed = REFINE_ANSWER_FIELDS[field];
  if (allowed === undefined) return false;
  if (allowed === 'text') return value.trim() !== '' && value.length <= 200;
  return allowed.includes(value);
}

function toQuestions(output: RefineOutput): RefinementQuestion[] {
  return output.questions.map((q, i): RefinementQuestion => {
    const options = q.options.filter((o) => q.field === '' || answerFieldAllowed(q.field, o.value));
    return {
      id: `RQ-${String(i + 1).padStart(2, '0')}`,
      question: q.question,
      why: q.why,
      // A question whose answers SecureVibe cannot apply is still worth asking; it just records the answer as a note.
      ...(q.field !== '' && options.length > 0 ? { field: q.field } : {}),
      options: options.map((o) => ({ label: o.label, value: o.value })),
      answered: false,
    };
  });
}

function toFeatures(output: RefineOutput): RefinementSuggestion[] {
  return output.features
    .filter((f) => answerFieldAllowed(f.field, f.value))
    .map((f, i): RefinementSuggestion => ({
      id: `RF-${String(i + 1).padStart(2, '0')}`,
      title: f.title,
      detail: f.detail,
      field: f.field,
      value: f.value,
      accepted: null,
    }));
}

export async function refineProfile(provider: LlmProvider, profile: PartialDesignProfile, opts: RefineOptions = {}): Promise<RefineOutcome> {
  const now = (opts.now ?? new Date()).toISOString();
  const skipped = (reason: string, summary: string): Refinement => ({
    performedBy: 'skipped',
    performedAt: now,
    summary,
    questions: [],
    features: [],
    skippedReason: reason,
  });

  if (provider.name === 'null') {
    return {
      refinement: skipped(
        'AI is not configured (preview mode)',
        'Follow-up questions need AI, which is not configured. Your answers are unchanged.',
      ),
      usage: emptyUsageDelta(provider.model),
    };
  }

  const user = [
    'THE OWNER’S ANSWERS SO FAR',
    '',
    renderPartialProfile(profile),
    '',
    'How they described the app, in their own words:',
    wrapUntrusted('user-description', profile.app?.description ?? '', { maxChars: 4000 }),
    '',
    'ANSWERS YOU MAY SET (field = one of these; value = one of its listed values, or free text where it says text):',
    ...Object.entries(REFINE_ANSWER_FIELDS).map(([k, v]) => `  ${k} = ${v === 'text' ? 'text' : v.join(' | ')}`),
    '',
    'Ask at most six questions, and only where the answers are missing or could mean two different things.',
    'Suggest at most eight features, each one thing the app clearly needs to do what they described.',
  ].join('\n');

  const result = await provider.structured({
    purpose: 'refine',
    system: refineSystem(),
    user,
    schema: RefineOutputSchema,
    effort: opts.effort ?? 'low',
    maxTokens: 8_000,
    correlationId: opts.correlationId ?? 'refine',
    projectId: opts.projectId ?? 'unknown',
    ...(opts.abort ? { abort: opts.abort } : {}),
  });

  if (!result.ok) {
    return {
      refinement: skipped(result.message, `The follow-up questions could not be prepared. ${result.message}`),
      usage: result.usage,
      failure: { reason: result.reason, message: result.message },
    };
  }

  return {
    refinement: {
      performedBy: 'claude',
      model: result.servedModel,
      performedAt: now,
      summary: result.data.summary,
      questions: toQuestions(result.data),
      features: toFeatures(result.data),
    },
    usage: result.usage,
  };
}
