/**
 * Splits a rendered Markdown table row into the cells a renderer would actually show.
 *
 * Written as a shared helper because getting it wrong is the whole trap. The obvious version —
 * `row.split(/(?<!\\)\|/)` — treats `\\|` as an escaped pipe, which is exactly the mistake the
 * escaping bug relies on: Markdown reads `\\` as an escaped backslash and the pipe after it is a
 * live delimiter. A test using the naive splitter passes whether or not the bug is present, which
 * is worse than having no test at all.
 */
export function markdownCells(row: string): string[] {
  const out: string[] = [];
  let current = '';
  for (let i = 0; i < row.length; i += 1) {
    const ch = row[i]!;
    if (ch === '\\') {
      // An escape consumes the next character, whatever it is — including another backslash.
      current += ch + (row[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (ch === '|') {
      out.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  out.push(current.trim());
  // A row starts and ends with a delimiter, so drop the empty pieces those produce.
  return out.slice(1, -1);
}
