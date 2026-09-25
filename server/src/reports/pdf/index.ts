/**
 * A report as a PDF file, written by SecureVibe itself: no browser, no print dialog, no dependency. The HTML the
 * report renderers already produce is read back and laid out on A4 pages with the fonts every PDF reader has.
 *
 * What that costs: only Western European letters and common punctuation can be shown. Emoji are dropped (each status
 * badge also carries its word) and any other character prints as "?". The HTML report remains the complete version.
 */
import { parseHtml, textOf, type HtmlNode } from './html.js';
import { layoutDocument } from './layout.js';
import { DEFAULT_PAGE_SIZE, writePdf, type PageSize } from './writer.js';

function findTitle(node: HtmlNode): string | undefined {
  for (const child of node.children) {
    if (typeof child === 'string') continue;
    if (child.tag === 'title') return textOf(child).trim();
    const inner = findTitle(child);
    if (inner) return inner;
  }
  return undefined;
}

export interface PdfOptions {
  title?: string;
  /** The paper: US Letter unless told otherwise. */
  pageSize?: PageSize;
  /** ISO timestamp recorded as the creation date, so the same report always produces the same file. */
  createdAt?: string;
}

export function htmlToPdf(html: string, options: PdfOptions = {}): Buffer {
  const root = parseHtml(html);
  const title = options.title ?? findTitle(root) ?? 'SecureVibe report';
  const { pages, outline } = layoutDocument(root, title, options.pageSize ?? DEFAULT_PAGE_SIZE);
  return writePdf(pages, outline, { title, size: options.pageSize ?? DEFAULT_PAGE_SIZE, createdAt: options.createdAt });
}

export { fullyRepresentable } from './fonts.js';
export { DEFAULT_PAGE_SIZE, PAGE_SIZES, pageSizeOf, type PageSize } from './writer.js';
