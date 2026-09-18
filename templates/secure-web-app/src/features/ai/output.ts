/**
 * What happens to a reply before anybody sees it (contract §1.11, step 5).
 *
 *  1. It must match the agreed shape, including the length bound. Anything else becomes the fixed fallback.
 *  2. It must not repeat the assistant's own instructions: a run of twelve identical words in a row is treated
 *     as disclosure, whatever wrapping is around it.
 *  3. It must not mention identifiers or email addresses of records the person is not allowed to see. This is
 *     the last line: even if something slipped into the context, it does not slip out.
 *  4. It is shown as text. The views print it with EJS' escaping tag, so no markup, markdown or link in it can
 *     do anything in the browser.
 */
import type { SessionUser } from '../auth/repo.ts';
import { get } from '../../db/index.ts';
import { listEntities } from '../../security/authz.ts';
import { AnswerSchema, type Answer } from './client.ts';
import { SYSTEM_PROMPT } from './prompt.ts';

/** Number of identical words in a row that counts as repeating the instructions. */
export const OVERLAP_WINDOW = 12;
export const MAX_ANSWER_CHARS = 4000;

const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
export const REDACTED = '[hidden]';

export type OutputRejection = { ok: false; reason: 'schema' | 'too-long' | 'system-prompt-disclosure' | 'refused' | 'moderation' };
export type OutputResult = { ok: true; answer: Answer } | OutputRejection;

// ---------------------------------------------------------------------------------------------------------
// Shape and length
// ---------------------------------------------------------------------------------------------------------

export function validateAnswer(candidate: unknown): OutputResult {
  const parsed = AnswerSchema.safeParse(candidate);
  if (!parsed.success) {
    const tooLong = parsed.error.issues.some((i) => i.code === 'too_big');
    return { ok: false, reason: tooLong ? 'too-long' : 'schema' };
  }
  if (parsed.data.answer.length > MAX_ANSWER_CHARS) return { ok: false, reason: 'too-long' };
  return { ok: true, answer: parsed.data };
}

// ---------------------------------------------------------------------------------------------------------
// System-prompt disclosure
// ---------------------------------------------------------------------------------------------------------

function words(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9<>|_/\s-]/g, ' ')
    .split(/\s+/)
    .filter((w) => w !== '');
}

function ngrams(list: string[], size: number): Set<string> {
  const out = new Set<string>();
  for (let i = 0; i + size <= list.length; i += 1) out.add(list.slice(i, i + size).join(' '));
  return out;
}

let promptNgrams: Set<string> | undefined;

/** True when the text repeats at least OVERLAP_WINDOW words of the system prompt in a row. */
export function disclosesSystemPrompt(text: string, prompt: string = SYSTEM_PROMPT): boolean {
  const reference = prompt === SYSTEM_PROMPT ? (promptNgrams ??= ngrams(words(prompt), OVERLAP_WINDOW)) : ngrams(words(prompt), OVERLAP_WINDOW);
  if (reference.size === 0) return false;
  for (const gram of ngrams(words(text), OVERLAP_WINDOW)) {
    if (reference.has(gram)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------------------
// Post-inference filter: identifiers and email addresses the person may not see
// ---------------------------------------------------------------------------------------------------------

/**
 * Looks an identifier up in every registered entity. Returns true when the identifier belongs to a record this
 * person is allowed to open (their own record, or any record for an administrator), or when it is not a record
 * of this application at all.
 */
export function maySeeIdentifier(id: string, user: SessionUser): boolean {
  if (user.isAdmin) return true;
  if (id === user.id) return true;
  for (const entity of listEntities()) {
    // Table and column names are validated identifiers when the entity is registered (src/security/authz.ts).
    const row = get<Record<string, unknown>>(`SELECT ${entity.ownerField} AS owner FROM ${entity.table} WHERE ${entity.idColumn ?? 'id'} = ?`, [id]);
    if (!row) continue;
    return row.owner === user.id;
  }
  return true;
}

/**
 * Removes identifiers and email addresses that do not belong to this person. Applied to the assistant's answer
 * and to anything else the assistant page shows back, so a record another person owns cannot be reflected
 * through the assistant.
 */
export function filterForUser(text: string, user: SessionUser): { text: string; redactions: number } {
  let redactions = 0;
  const withoutIds = text.replace(UUID, (match) => {
    if (maySeeIdentifier(match, user)) return match;
    redactions += 1;
    return REDACTED;
  });
  const ownEmail = user.email.toLowerCase();
  const withoutEmails = withoutIds.replace(EMAIL, (match) => {
    if (user.isAdmin || match.toLowerCase() === ownEmail) return match;
    redactions += 1;
    return REDACTED;
  });
  return { text: withoutEmails, redactions };
}
