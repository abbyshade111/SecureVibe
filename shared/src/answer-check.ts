/**
 * A check for damaged saved answers.
 *
 * Both of the owner's first apps had a record type that no person could have written: one with no details at
 * all, one whose name was a sentence cut off mid-word. They come from a follow-up answer or a repair being
 * taken as a record, and a rebuild recreates them from the answers every time, so the answers are where they
 * must be found. This looks at the saved answers and says what looks wrong and why, in plain words. It never
 * changes anything: an offer to remove is the owner's to accept, and a question is theirs to answer.
 */
import type { PartialDesignProfile } from './profile.js';

export type AnswerProblemKind =
  /** A record type with no details cannot have come from someone describing a record: offer to remove it. */
  | 'record-without-details'
  /** A name that reads as a sentence, or is cut off at the length limit, is a question rather than an offer. */
  | 'record-name-looks-like-a-sentence'
  /** A description that begins "yes" or "no", or repeats the app's own description, answered something else. */
  | 'record-description-answers-another-question';

export interface AnswerProblem {
  kind: AnswerProblemKind;
  /** Index into app.entities, so the page can point at the record and the owner can remove it. */
  entityIndex: number;
  /** The record's label as saved, for the message. */
  label: string;
  /** What looks wrong, and what the owner can do about it, in plain words. */
  message: string;
  /** True when removing the record is the obvious fix; false when only the owner can say. */
  offerRemoval: boolean;
}

/** The label length the record editor and the follow-up flow both cut at. */
const LABEL_LIMIT = 60;

function looksLikeASentence(label: string): boolean {
  const trimmed = label.trim();
  // The same rule the follow-up flow refuses a record name with (design/refine-apply.ts), applied after the fact.
  if (trimmed.length > 40 || /\band\b/i.test(trimmed)) return true;
  // Cut off at the limit, and not at a word boundary: "...entries as separate rec".
  if (trimmed.length >= LABEL_LIMIT && !/[.!?)]$/.test(trimmed)) return true;
  return false;
}

export function checkSavedAnswers(profile: PartialDesignProfile): AnswerProblem[] {
  const problems: AnswerProblem[] = [];
  const entities = profile.app?.entities ?? [];
  const appDescription = (profile.app?.description ?? '').trim().toLowerCase();

  entities.forEach((entity, entityIndex) => {
    const label = (entity.label ?? '').trim();
    // A record still being typed (blank name) is the editor's business, not a damaged answer.
    if (label === '') return;

    if ((entity.fields ?? []).length === 0) {
      problems.push({
        kind: 'record-without-details',
        entityIndex,
        label,
        message: `"${label}" has no details. A record with nothing to fill in gives its page an empty form, and nobody describing a record leaves it that way, so this most likely arrived by accident. Remove it, or add the details it should hold.`,
        offerRemoval: true,
      });
    }

    if (looksLikeASentence(label)) {
      problems.push({
        kind: 'record-name-looks-like-a-sentence',
        entityIndex,
        label,
        message: `"${label}" reads like a sentence rather than the name of a record, as if an answer was taken as a record type. If it is not something your app keeps, remove it; if it is, give it a short name.`,
        offerRemoval: false,
      });
    }

    const description = (entity.description ?? '').trim();
    if (description !== '' && (/^(yes|no)\b/i.test(description) || (appDescription !== '' && description.toLowerCase() === appDescription))) {
      problems.push({
        kind: 'record-description-answers-another-question',
        entityIndex,
        label,
        message: `The description of "${label}" reads like the answer to a different question. Check it says what this record is for.`,
        offerRemoval: false,
      });
    }
  });

  return problems;
}
