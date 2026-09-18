/** A plain HTML table builder. Cells are pre-rendered HTML (already escaped by the caller via escapeHtml or a badge helper). */

export interface TableOptions {
  /** Wraps the whole table in an id'd <div class="hideable ..."> and marks rows via `rowClass(row, index)`. */
  id?: string;
  caption?: string;
  rowClass?: (index: number) => string | undefined;
}

export function htmlTable(headers: string[], rows: string[][], opts: TableOptions = {}): string {
  if (rows.length === 0) return '<p class="muted">None.</p>';
  const head = `<tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr>`;
  const body = rows
    .map((row, i) => {
      const cls = opts.rowClass?.(i);
      return `<tr${cls ? ` class="${cls}"` : ''}>${row.map((c) => `<td>${c}</td>`).join('')}</tr>`;
    })
    .join('\n');
  const caption = opts.caption ? `<caption>${opts.caption}</caption>` : '';
  return `<table${opts.id ? ` id="${opts.id}"` : ''}>${caption}<thead>${head}</thead><tbody>${body}</tbody></table>`;
}

export function htmlList(items: string[], empty = '<p class="muted">None.</p>'): string {
  if (items.length === 0) return empty;
  return `<ul>${items.map((i) => `<li>${i}</li>`).join('\n')}</ul>`;
}
