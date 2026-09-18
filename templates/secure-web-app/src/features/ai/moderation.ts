/**
 * Optional content moderation (contract §1.11, last paragraph). When it is switched on, a separate
 * classification call scores the question before it is sent and the answer before it is shown. The classifier
 * never sees the assistant's instructions, and every decision is recorded as ai.moderation.decision.
 */
import type { Request } from 'express';
import { emit } from '../../security/events.ts';
import { logger } from '../../lib/logger.ts';
import { aiClient, AiUnavailableError, type ModerationScores } from './client.ts';

/** Score above which content is refused. Override with AI_MODERATION_THRESHOLD (0 to 1). */
export const DEFAULT_THRESHOLD = 0.8;

export function threshold(): number {
  const raw = Number(process.env.AI_MODERATION_THRESHOLD ?? '');
  return Number.isFinite(raw) && raw > 0 && raw <= 1 ? raw : DEFAULT_THRESHOLD;
}

export interface ModerationDecision {
  allowed: boolean;
  /** The category that crossed the threshold, when one did. */
  category?: string;
  score: number;
  /** True when the classifier could not be reached; the caller decides what to do. */
  unavailable: boolean;
}

function worst(scores: ModerationScores): { category: string; score: number } {
  let category = 'violence';
  let score = -1;
  for (const [name, value] of Object.entries(scores)) {
    if (value > score) {
      category = name;
      score = value;
    }
  }
  return { category, score: Math.max(0, score) };
}

/**
 * Classifies one piece of text. `stage` is 'input' or 'output'. A classifier that cannot be reached is logged
 * and reported as unavailable — the caller keeps the decision, so a broken classifier never silently disappears.
 */
export async function moderate(req: Request, stage: 'input' | 'output', text: string): Promise<ModerationDecision> {
  const limit = threshold();
  try {
    const scores = await aiClient().classify(text, stage);
    const top = worst(scores);
    const allowed = top.score < limit;
    emit('ai.moderation.decision', {
      req,
      stage,
      category: top.category,
      score: Math.round(top.score * 100) / 100,
      threshold: limit,
      outcome: allowed ? 'success' : 'blocked',
      decision: allowed ? 'allowed' : 'blocked',
    });
    return { allowed, category: allowed ? undefined : top.category, score: top.score, unavailable: false };
  } catch (err) {
    const detail = err instanceof AiUnavailableError ? err.reason : 'unknown';
    logger.warn({ stage, detail }, 'the moderation check could not be made');
    emit('ai.moderation.decision', { req, stage, decision: 'unavailable', detail, outcome: 'failure' });
    return { allowed: false, score: 0, unavailable: true };
  }
}
