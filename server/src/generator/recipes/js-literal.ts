/**
 * Writing a value into generated JavaScript as a string literal.
 *
 * Recipes emit code by building a template literal, and the values they interpolate are typed by the owner:
 * a record type's label, its plural, a field's name. Dropping one of those straight between single quotes
 * works until somebody calls a record type "Client's habit" — an ordinary English label — and the app comes
 * out with
 *
 *     req.session.flash('success', 'Client's habit saved.');
 *
 * which is not JavaScript. The build then fails somewhere far from the label that caused it, or the recipe
 * quietly writes a file nobody can parse.
 *
 * Escaping the quote alone is not enough either: a label ending in a backslash turns the escape into an
 * escaped backslash followed by a live quote, which is the same bug one character along.
 *
 * So the value is written as a JSON string, which handles quotes, backslashes, control characters and
 * newlines together — plus the two line separators JSON allows raw, and the less-than sign, so the result is
 * also safe to drop inside a script block or an EJS tag.
 */

/** `value` as a JavaScript string literal, quotes included, safe to paste into emitted code. */
export function jsString(value: string): string {
  // The two separators are written as regex escapes, never as the raw characters: a raw U+2028 in this file
  // is itself a line terminator, and the bug this helper exists to prevent is perfectly capable of biting
  // the helper. Written as three replace() calls rather than split/join because that is the one shape CodeQL's
  // "bad code sanitization" rule recognizes as the fix; split/join did the same thing and left seventeen
  // alerts standing on the emitter (24 September 2026). The three-replace shape is load-bearing for the scanner:
  // the rule fires once per call site, so tidying this into anything else reopens every alert on the emitter.
  // Keep the file free of raw U+2028/U+2029 characters, tests included (build one with String.fromCharCode).
  return JSON.stringify(value)
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
    .replace(/</g, '\\u003c');
}

/**
 * `value` made safe to drop inside a block comment in emitted code.
 *
 * A label is written into the header comment of the file the recipe generates. A label containing the
 * characters that close a block comment would end it early, and everything after would be parsed as code.
 * Nobody calls a record type that, which is exactly why it would go unnoticed.
 */
export function commentText(value: string): string {
  return value.split('*/').join('* /').split(/[\r\n]+/).join(' ');
}
