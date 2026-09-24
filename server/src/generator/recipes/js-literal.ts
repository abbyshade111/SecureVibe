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
  // Built from character codes rather than written out: a raw U+2028 in this file is itself a line
  // terminator, so a regex containing one does not parse. The bug this helper exists to prevent is
  // perfectly capable of biting the helper.
  const lineSeparator = String.fromCharCode(0x2028);
  const paragraphSeparator = String.fromCharCode(0x2029);
  return JSON.stringify(value)
    .split(lineSeparator)
    .join('\\u2028')
    .split(paragraphSeparator)
    .join('\\u2029')
    .split('<')
    .join('\\u003c');
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
