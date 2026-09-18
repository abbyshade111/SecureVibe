import { WIZARD_STEPS } from '@shared/api.js';

/** The wizard's question steps, in order (the summary, build and results pages are not question steps). */
export const QUESTION_STEP_IDS = WIZARD_STEPS.filter((s) => !['summary', 'build', 'results'].includes(s.id)).map((s) => s.id);

/** Where to continue an unfinished app: the step the person last reached. */
export function resumeStepId(wizardStep: number | undefined): string {
  return QUESTION_STEP_IDS[Math.min(Math.max(wizardStep ?? 0, 0), QUESTION_STEP_IDS.length - 1)] ?? 'about';
}
