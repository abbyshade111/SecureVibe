/** Small Markdown table/list helpers shared by the compliance and security report renderers. */

function cell(text: string | number | boolean | undefined): string {
  if (text === undefined) return '';
  return String(text).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function mdTable(headers: string[], rows: (string | number | boolean | undefined)[][]): string {
  if (rows.length === 0) return '_none_';
  const lines = [`| ${headers.map(cell).join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`];
  for (const row of rows) lines.push(`| ${row.map(cell).join(' | ')} |`);
  return lines.join('\n');
}

export function mdBullets(items: string[], empty = '_none_'): string {
  return items.length ? items.map((i) => `- ${i}`).join('\n') : empty;
}

export function mdHeading(level: number, text: string, anchorComment?: string): string {
  return `${'#'.repeat(level)} ${text}${anchorComment ? ` <!-- #${anchorComment} -->` : ''}`;
}

export function mdSection(...parts: (string | undefined | false)[]): string {
  return parts.filter((p): p is string => Boolean(p)).join('\n\n');
}
