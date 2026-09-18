/**
 * Two small flows that round out the prompt library:
 *  - `classifyText` scores a piece of text a person typed, for the moderation setting (AISVS C2.2.1);
 *  - `summarizePlain` rewrites technical security text for the owner (used where a report needs plain language).
 *
 * Both treat their input strictly as data, and both fail closed: when the AI is not available the caller gets a clear
 * "not done" rather than a made-up answer.
 */
import { z } from 'zod';
import { classifySystem, summarizeSystem, wrapUntrusted } from '../prompts/index.js';
import { loadDefaultInjectionPatterns, screenText, type InjectionPatterns } from '../screening.js';
import { emptyUsageDelta, type Effort, type LlmProvider, type StructuredFailureReason, type UsageDelta } from '../types.js';

export const ClassificationSchema = z.strictObject({
  violence: z.number(),
  selfHarm: z.number(),
  hate: z.number(),
  sexual: z.number(),
  /** Whether the text reads as a description of software someone wants built. */
  isAppDescription: z.boolean(),
  note: z.string().max(400),
});
export type Classification = z.infer<typeof ClassificationSchema>;

export interface ClassifyOptions {
  projectId?: string;
  correlationId?: string;
  effort?: Effort;
  injectionPatterns?: InjectionPatterns;
}

export interface ClassifyOutcome {
  ok: boolean;
  classification?: Classification;
  /** Highest category score, for a simple threshold check by the caller. */
  worstScore: number;
  usage: UsageDelta;
  failure?: { reason: StructuredFailureReason; message: string };
}

export async function classifyText(provider: LlmProvider, text: string, opts: ClassifyOptions = {}): Promise<ClassifyOutcome> {
  const patterns = opts.injectionPatterns ?? loadDefaultInjectionPatterns();
  const screening = screenText(text, patterns);

  const result = await provider.structured({
    purpose: 'classify',
    system: classifySystem(),
    user: [
      wrapUntrusted('user-text', text, { maxChars: 8000, ...(screening.flagged ? { screeningNote: screening.note } : {}) }),
      '',
      'Score each category between 0 (not present) and 1 (clearly present).',
    ].join('\n'),
    schema: ClassificationSchema,
    effort: opts.effort ?? 'low',
    maxTokens: 2000,
    correlationId: opts.correlationId ?? 'classify',
    projectId: opts.projectId ?? 'unknown',
  });

  if (!result.ok) {
    return { ok: false, worstScore: 0, usage: result.usage, failure: { reason: result.reason, message: result.message } };
  }
  const c = result.data;
  return {
    ok: true,
    classification: c,
    worstScore: Math.max(c.violence, c.selfHarm, c.hate, c.sexual),
    usage: result.usage,
  };
}

export const SummarySchema = z.strictObject({
  plain: z.string().max(4000),
  /** One short sentence saying what it means for the person in practice. */
  whatItMeans: z.string().max(500),
});
export type Summary = z.infer<typeof SummarySchema>;

export interface SummarizeOutcome {
  ok: boolean;
  summary?: Summary;
  usage: UsageDelta;
  failure?: { reason: StructuredFailureReason; message: string };
}

export async function summarizePlain(
  provider: LlmProvider,
  input: { text: string; audience?: string; projectId?: string; correlationId?: string; effort?: Effort },
): Promise<SummarizeOutcome> {
  if (provider.name === 'null') {
    return {
      ok: false,
      usage: emptyUsageDelta(provider.model),
      failure: { reason: 'error', message: 'AI is not configured (preview mode)' },
    };
  }

  const result = await provider.structured({
    purpose: 'summarize',
    system: summarizeSystem(),
    user: [
      `Write for: ${input.audience ?? 'the owner of a small business, with no technical background'}.`,
      '',
      wrapUntrusted('security-tool-output', input.text, { maxChars: 12_000 }),
    ].join('\n'),
    schema: SummarySchema,
    effort: input.effort ?? 'low',
    maxTokens: 4000,
    correlationId: input.correlationId ?? 'summarize',
    projectId: input.projectId ?? 'unknown',
  });

  if (!result.ok) {
    return { ok: false, usage: result.usage, failure: { reason: result.reason, message: result.message } };
  }
  return { ok: true, summary: result.data, usage: result.usage };
}
