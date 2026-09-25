/**
 * The bytes of a PDF: objects, cross-reference table, compressed page streams. Nothing here knows about reports; it
 * takes finished pages (drawing operators as text) and writes them out. PDF 1.4, the five standard fonts, no images.
 */
import { deflateSync } from 'node:zlib';
import { FONTS, type FontKey } from './fonts.js';

export const PAGE_WIDTH = 595.28;
export const PAGE_HEIGHT = 841.89;

export interface PageLink {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  uri: string;
}

export interface PdfPage {
  ops: string;
  links: PageLink[];
}

export interface OutlineEntry {
  title: string;
  page: number;
  /** Distance from the top of the page, in points. */
  y: number;
}

export interface PdfMeta {
  title: string;
  /** ISO timestamp for the creation date; left out when it does not parse. */
  createdAt?: string;
}

/** A PDF "text string": PDFDocEncoding is close to Latin-1, but UTF-16 with a byte-order mark is always right. */
function textString(text: string): string {
  const units: string[] = ['feff'];
  for (let i = 0; i < text.length; i++) units.push(text.charCodeAt(i).toString(16).padStart(4, '0'));
  return `<${units.join('')}>`;
}

function literal(text: string): string {
  return `(${text.replace(/[\\()]/g, '\\$&').replace(/[^\x20-\x7e]/g, '?')})`;
}

function pdfDate(iso: string | undefined): string | undefined {
  const d = iso ? new Date(iso) : undefined;
  if (!d || Number.isNaN(d.getTime())) return undefined;
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `D:${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

const num = (n: number) => (Math.round(n * 100) / 100).toString();

export function writePdf(pages: PdfPage[], outline: OutlineEntry[], meta: PdfMeta): Buffer {
  const objects: Buffer[] = []; // objects[i] is object number i + 1
  const add = (body: string | Buffer): number => {
    objects.push(Buffer.isBuffer(body) ? body : Buffer.from(body, 'latin1'));
    return objects.length;
  };
  const reserve = (): number => add('');
  const set = (id: number, body: string | Buffer) => {
    objects[id - 1] = Buffer.isBuffer(body) ? body : Buffer.from(body, 'latin1');
  };

  const catalog = reserve();
  const pagesRoot = reserve();
  const info = reserve();
  const fontIds = {} as Record<FontKey, number>;
  for (const key of Object.keys(FONTS) as FontKey[]) {
    fontIds[key] = add(`<< /Type /Font /Subtype /Type1 /BaseFont /${FONTS[key]} /Encoding /WinAnsiEncoding >>`);
  }
  const fontDict = `<< ${(Object.keys(fontIds) as FontKey[]).map((k) => `/${k} ${fontIds[k]} 0 R`).join(' ')} >>`;

  const pageIds = pages.map(() => reserve());
  pages.forEach((page, index) => {
    const raw = deflateSync(Buffer.from(page.ops, 'latin1'));
    const stream = add(Buffer.concat([Buffer.from(`<< /Length ${raw.length} /Filter /FlateDecode >>\nstream\n`, 'latin1'), raw, Buffer.from('\nendstream', 'latin1')]));
    const annots = page.links.map((l) =>
      add(`<< /Type /Annot /Subtype /Link /Rect [${num(l.x1)} ${num(l.y1)} ${num(l.x2)} ${num(l.y2)}] /Border [0 0 0] /A << /S /URI /URI ${literal(l.uri)} >> >>`),
    );
    set(
      pageIds[index]!,
      `<< /Type /Page /Parent ${pagesRoot} 0 R /MediaBox [0 0 ${num(PAGE_WIDTH)} ${num(PAGE_HEIGHT)}] /Resources << /Font ${fontDict} >> /Contents ${stream} 0 R${annots.length ? ` /Annots [${annots.map((a) => `${a} 0 R`).join(' ')}]` : ''} >>`,
    );
  });
  set(pagesRoot, `<< /Type /Pages /Kids [${pageIds.map((p) => `${p} 0 R`).join(' ')}] /Count ${pageIds.length} >>`);

  let outlineRoot: number | undefined;
  if (outline.length > 0) {
    outlineRoot = reserve();
    const items = outline.map(() => reserve());
    outline.forEach((entry, i) => {
      const page = pageIds[Math.min(entry.page, pageIds.length - 1)]!;
      const parts = [
        `/Title ${textString(entry.title)}`,
        `/Parent ${outlineRoot} 0 R`,
        `/Dest [${page} 0 R /XYZ 0 ${num(PAGE_HEIGHT - entry.y)} null]`,
        i > 0 ? `/Prev ${items[i - 1]} 0 R` : '',
        i < items.length - 1 ? `/Next ${items[i + 1]} 0 R` : '',
      ];
      set(items[i]!, `<< ${parts.filter(Boolean).join(' ')} >>`);
    });
    set(outlineRoot, `<< /Type /Outlines /First ${items[0]} 0 R /Last ${items[items.length - 1]} 0 R /Count ${items.length} >>`);
  }

  set(catalog, `<< /Type /Catalog /Pages ${pagesRoot} 0 R /Lang (en-US) /ViewerPreferences << /DisplayDocTitle true >>${outlineRoot ? ` /Outlines ${outlineRoot} 0 R /PageMode /UseOutlines` : ''} >>`);
  const date = pdfDate(meta.createdAt);
  set(info, `<< /Title ${textString(meta.title)} /Producer (SecureVibe) /Creator (SecureVibe)${date ? ` /CreationDate (${date})` : ''} >>`);

  const chunks: Buffer[] = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  const offsets: number[] = [];
  let position = chunks[0]!.length;
  objects.forEach((body, i) => {
    offsets.push(position);
    const piece = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, 'latin1'), body, Buffer.from('\nendobj\n', 'latin1')]);
    chunks.push(piece);
    position += piece.length;
  });
  const xref = [`xref\n0 ${objects.length + 1}\n`, '0000000000 65535 f \n', ...offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`)].join('');
  chunks.push(Buffer.from(`${xref}trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${position}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(chunks);
}
