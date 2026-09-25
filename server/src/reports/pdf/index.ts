/**
 * A report as a PDF file, written by SecureVibe itself: no browser, no print dialog, no dependency. The HTML the
 * report renderers already produce is read back and laid out on A4 pages with the fonts every PDF reader has.
 *
 * What that costs: only Western European letters and common punctuation can be shown. Emoji are dropped (each status
 * badge also carries its word) and any other character prints as "?". The HTML report remains the complete version.
 */
import { parseHtml, textOf, type HtmlNode } from './html.js';
import { layoutDocument } from './layout.js';
import { writePdf } from './writer.js';

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
  /** ISO timestamp recorded as the creation date, so the same report always produces the same file. */
  createdAt?: string;
}

export function htmlToPdf(html: string, options: PdfOptions = {}): Buffer {
  const root = parseHtml(html);
  const title = options.title ?? findTitle(root) ?? 'SecureVibe report';
  const { pages, outline } = layoutDocument(root, title);
  return writePdf(pages, outline, { title, createdAt: options.createdAt });
}

export { fullyRepresentable } from './fonts.js';
