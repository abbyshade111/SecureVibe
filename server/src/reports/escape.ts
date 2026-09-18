/** HTML/CSS-id escaping shared by every report renderer. Every value written into a report goes through this. */

const HTML_ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(value: unknown): string {
  if (value === undefined || value === null) return '';
  return String(value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]!);
}

/** A stable, URL-safe anchor id for a requirement/finding/control id ("V6.2.1" -> "r-v6-2-1"). */
export function anchorId(prefix: string, id: string): string {
  return `${prefix}-${id.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')}`;
}

export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}
