/**
 * A small tokenizer for EJS templates. It splits a template into EJS tags and the HTML between them,
 * and produces a "masked" copy of the text (same length, same offsets) in which every tag is replaced
 * by a placeholder, so HTML rules can use regular expressions without tripping over `%>`.
 */

export type EjsTagKind = 'scriptlet' | 'escaped' | 'unescaped' | 'comment' | 'literal';

export interface EjsTag {
  kind: EjsTagKind;
  /** The JavaScript inside the tag, trimmed. */
  code: string;
  /** Offset of `<%` in the original text. */
  start: number;
  /** Offset just after `%>`. */
  end: number;
  line: number;
  column: number;
}

export interface EjsDocument {
  text: string;
  tags: EjsTag[];
  /** The text with every EJS tag replaced by a same-length placeholder (output tags keep `{{name}}`). */
  masked: string;
  lineOf(offset: number): number;
  columnOf(offset: number): number;
}

const OPEN = '<%';
const CLOSE = '%>';

export function tokenizeEjs(text: string): EjsDocument {
  const tags: EjsTag[] = [];
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineOf = (offset: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((lineStarts[mid] ?? 0) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const columnOf = (offset: number): number => offset - (lineStarts[lineOf(offset) - 1] ?? 0) + 1;

  let pos = 0;
  const maskedParts: string[] = [];
  while (pos < text.length) {
    const open = text.indexOf(OPEN, pos);
    if (open === -1) {
      maskedParts.push(text.slice(pos));
      break;
    }
    maskedParts.push(text.slice(pos, open));
    // `<%%` is an escaped literal "<%" and has no closing tag.
    if (text.startsWith('<%%', open)) {
      tags.push({ kind: 'literal', code: '', start: open, end: open + 3, line: lineOf(open), column: columnOf(open) });
      maskedParts.push('   ');
      pos = open + 3;
      continue;
    }
    const close = text.indexOf(CLOSE, open + 2);
    const end = close === -1 ? text.length : close + 2;
    const raw = text.slice(open, end);
    const marker = raw.charAt(2);
    let kind: EjsTagKind = 'scriptlet';
    let codeStart = 2;
    if (marker === '=') {
      kind = 'escaped';
      codeStart = 3;
    } else if (marker === '-') {
      kind = 'unescaped';
      codeStart = 3;
    } else if (marker === '#') {
      kind = 'comment';
      codeStart = 3;
    } else if (marker === '_') {
      codeStart = 3;
    }
    let inner = close === -1 ? raw.slice(codeStart) : raw.slice(codeStart, raw.length - 2);
    // Trailing `-` / `_` before `%>` are whitespace-control markers, not code.
    inner = inner.replace(/[-_]$/, '');
    const code = inner.trim();
    tags.push({ kind, code, start: open, end, line: lineOf(open), column: columnOf(open) });
    maskedParts.push(placeholderFor(kind, code, raw));
    pos = end;
  }
  const masked = maskedParts.join('');
  return { text, tags, masked, lineOf, columnOf };
}

/** Same length as `raw`; output tags of a plain identifier become `{{identifier}}` (padded) so HTML rules can see them. */
function placeholderFor(kind: EjsTagKind, code: string, raw: string): string {
  const blank = raw.replace(/[^\n]/g, ' ');
  if ((kind === 'escaped' || kind === 'unescaped') && /^[A-Za-z_$][\w$]*$/.test(code)) {
    const token = `{{${code}}}`;
    if (token.length <= raw.length && !raw.includes('\n')) return token + ' '.repeat(raw.length - token.length);
  }
  return blank;
}

/** Matches an EJS output of the `nonce` variable inside an attribute value (`nonce="<%= nonce %>"`). */
export const NONCE_ATTR = /\bnonce\s*=\s*["']\s*\{\{nonce\}\}\s*["']/i;
