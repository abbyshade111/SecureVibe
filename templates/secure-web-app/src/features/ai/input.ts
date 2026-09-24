/**
 * Everything that happens to a message before any of it reaches the model (contract §1.11, steps 1 and 2).
 *
 * The order matters: normalize to one standard form first, then take out the invisible characters that exist
 * only to hide text, then refuse anything that is still not plain readable text, then refuse the sequences and
 * encodings that are used to smuggle instructions past a screen. Over-long input is refused outright — it is
 * never shortened, because a silent cut is a silent change of meaning.
 */

/** Characters that carry no visible meaning: format characters, zero-width marks, bidi controls, the BOM. */
const INVISIBLE = /[\p{Cf}\p{Co}\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\ufeff]/gu;
/** What is left must be printable text plus newline and tab. */
const DISALLOWED_CONTROL = /[\p{Cc}\p{Cs}]/u;
const ALLOWED_CONTROL = /[\n\t]/;
/** The replacement character means the text arrived broken (or was smuggled through a broken encoding). */
const REPLACEMENT_CHARACTER = '\ufffd';

/** Sequences that chat models treat as structure rather than text. They may never enter the context. */
export const RESERVED_SEQUENCES = ['<|', '|>', '[INST]', '[/INST]', '<<SYS>>', '<</SYS>>'] as const;

/** Longest run of encoded-looking characters allowed inside a message. */
export const MAX_ENCODED_RUN = 200;
const BASE64_RUN = /[A-Za-z0-9+/=_-]{201,}/g;
const HEX_RUN = /[0-9a-fA-F]{201,}/g;

export type InputRejection = {
  ok: false;
  /** 400 for text this app will not accept, 422 for text that is well-formed but too long or too dense. */
  status: 400 | 422;
  /** Recorded as the `reason` field of ai.input.rejected. */
  reason: 'empty' | 'control-characters' | 'invalid-encoding' | 'reserved-sequence' | 'too-long' | 'encoded-run';
  /** Plain-language message for the person. */
  message: string;
  detail?: string;
};

export type InputResult = { ok: true; text: string } | InputRejection;

/** NFKC, so the same text always looks the same to every later check. */
export function normalise(raw: string): string {
  return raw.normalize('NFKC');
}

/** Removes the invisible characters. Everything removed here is meaningless to a reader. */
export function stripInvisible(text: string): string {
  return text.replace(INVISIBLE, '');
}

/** Counts how many characters a run uses, to tell real encoded data from a long repeated character. */
function distinctCharacters(run: string): number {
  return new Set(run).size;
}

/**
 * A long run of base64/hex-looking characters is how instructions are hidden from a screen. A long run of one
 * repeated character ("aaaa…") is not encoded data, so it is judged on length alone, not treated as smuggling.
 */
function findEncodedRun(text: string): string | undefined {
  for (const pattern of [BASE64_RUN, HEX_RUN]) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const run = match[0];
      if (distinctCharacters(run) >= 8) return run;
    }
  }
  return undefined;
}

/** Turns a reserved sequence into a literal so it can be shown back to the person without meaning anything. */
export function escapeReserved(text: string): string {
  let out = text;
  for (const sequence of RESERVED_SEQUENCES) {
    out = out.split(sequence).join(sequence.split('').join('\u200b'));
  }
  return out;
}

/**
 * Runs the whole input stage. `maxChars` is AI_MAX_INPUT_CHARS.
 * Returns the cleaned text, or the reason it was refused together with the status to answer with.
 */
export function prepareInput(raw: string, maxChars: number): InputResult {
  const cleaned = stripInvisible(normalise(raw)).trim();

  if (cleaned === '') {
    return { ok: false, status: 400, reason: 'empty', message: 'Please write a question for the assistant.' };
  }
  if (cleaned.includes(REPLACEMENT_CHARACTER)) {
    return {
      ok: false,
      status: 400,
      reason: 'invalid-encoding',
      message: 'Your message contains characters this app cannot read. Please retype it and try again.',
    };
  }
  for (const character of cleaned) {
    if (DISALLOWED_CONTROL.test(character) && !ALLOWED_CONTROL.test(character)) {
      return {
        ok: false,
        status: 400,
        reason: 'control-characters',
        message: 'Your message contains hidden control characters. Please retype it as plain text and try again.',
        detail: `U+${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
      };
    }
  }
  for (const sequence of RESERVED_SEQUENCES) {
    if (cleaned.includes(sequence)) {
      return {
        ok: false,
        status: 400,
        reason: 'reserved-sequence',
        message: 'Your message contains a sequence this app does not send to the assistant. Please rephrase it.',
        detail: sequence,
      };
    }
  }
  if (cleaned.length > maxChars) {
    return {
      ok: false,
      status: 422,
      reason: 'too-long',
      message: `Your message is ${cleaned.length} characters long. Please shorten it to ${maxChars} characters or fewer — nothing is cut off automatically.`,
    };
  }
  const run = findEncodedRun(cleaned);
  if (run !== undefined) {
    return {
      ok: false,
      status: 422,
      reason: 'encoded-run',
      message: `Your message contains a long run of encoded text (${run.length} characters). Please write the question in plain words.`,
    };
  }
  return { ok: true, text: cleaned };
}
