import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inflateSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { renderComplianceReport } from '../../src/reports/compliance-report.js';
import { renderGoingOnline } from '../../src/reports/going-online.js';
import { renderOverview } from '../../src/reports/overview.js';
import { renderSecurityReport } from '../../src/reports/security-report.js';
import { textWidth, fullyRepresentable } from '../../src/reports/pdf/fonts.js';
import { decodeEntities } from '../../src/reports/pdf/html.js';
import { htmlToPdf } from '../../src/reports/pdf/index.js';
import type { ReportModel } from '../../src/reports/types.js';
import { buildReportModel } from '../fixtures/reports/model.js';

// A PDF read back the way a reader would: the cross-reference table, then each page's text, with where it sits.
interface TextOp {
  page: number;
  font: string;
  size: number;
  x: number;
  y: number;
  text: string;
}

const WIN_ANSI_HIGH: Record<number, string> = { 0x91: '‘', 0x92: '’', 0x93: '“', 0x94: '”', 0x95: '•', 0x96: '–', 0x97: '—', 0x85: '…' };

function readPdf(pdf: Buffer) {
  const raw = pdf.toString('latin1');
  const start = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(raw)?.[1]);
  expect(raw.slice(start, start + 4), 'startxref must point at the xref table').toBe('xref');
  const size = Number(/xref\n0 (\d+)\n/.exec(raw.slice(start))?.[1]);
  const entries = [...raw.slice(start).matchAll(/(\d{10}) (\d{5}) ([nf]) \n/g)];
  expect(entries.length).toBe(size);
  entries.forEach((e, i) => {
    if (e[3] === 'n') expect(raw.slice(Number(e[1]), Number(e[1]) + `${i} 0 obj`.length), `object ${i}`).toBe(`${i} 0 obj`);
  });
  const pageCount = (raw.match(/\/Type \/Page /g) ?? []).length;
  expect(Number(/\/Count (\d+)/.exec(raw)?.[1])).toBe(pageCount);

  const ops: TextOp[] = [];
  let page = 0;
  for (const m of raw.matchAll(/\/Filter \/FlateDecode >>\nstream\n/g)) {
    const from = m.index! + m[0].length;
    const to = raw.indexOf('\nendstream', from);
    const content = inflateSync(pdf.subarray(from, to)).toString('latin1');
    page++;
    for (const op of content.matchAll(/BT \/(F\d) ([\d.]+) Tf [\d. ]+ rg ([\d.]+) ([\d.]+) Td <([0-9a-f]*)> Tj ET/g)) {
      const bytes = op[5]!.match(/../g) ?? [];
      const text = bytes.map((b) => WIN_ANSI_HIGH[parseInt(b, 16)] ?? String.fromCharCode(parseInt(b, 16))).join('');
      ops.push({ page, font: op[1]!, size: Number(op[2]), x: Number(op[3]), y: Number(op[4]), text });
    }
  }
  return { raw, pageCount, ops, text: ops.map((o) => o.text).join('\n') };
}

const wrapHtml = (body: string, title = 'Test report') => `<!doctype html><html><head><title>${title}</title><style>body{}</style></head><body><div class="page"><main>${body}</main></div></body></html>`;

/** Cuts every match of `pattern` out of `html` (split and rejoin, so no replacement can leave a half-removed tag behind). */
const cutOut = (html: string, pattern: RegExp): string => html.split(pattern).join('');
const HIDDEN_ROWS = /<(?:tr|li)\b[^>]*class="[^"]*\bhideable\b[^"]*"[^>]*>[\s\S]*?<\/(?:tr|li)>/g;

/** The text a reader of the web page sees, read separately from the code under test: no tags, nothing the page hides. */
function webPageText(html: string, { withPre = true }: { withPre?: boolean } = {}): string {
  let s = cutOut(html, /<style>[\s\S]*?<\/style>/g);
  s = cutOut(s, HIDDEN_ROWS);
  s = cutOut(s, /<(?:a class="skip-link"|label)[^>]*>[\s\S]*?<\/(?:a|label)>/g); // on-screen controls, not printed
  if (!withPre) s = cutOut(s, /<pre>[\s\S]*?<\/pre>/g); // preformatted text is cut by character, not by word
  return decodeEntities(s.split(/<[^>]*>/).join(' '));
}

describe('htmlToPdf: the file', () => {
  it('is a well-formed PDF: every cross-reference entry lands on its object, and the page count is true', () => {
    const { pageCount } = readPdf(htmlToPdf(wrapHtml('<h2>One</h2><p>Some text.</p>')));
    expect(pageCount).toBe(1);
  });

  it('carries the title and a bookmark for every chapter heading, and is byte-for-byte the same when made twice', () => {
    const html = wrapHtml('<h2>First chapter</h2><p>a</p><h2>Second chapter</h2><p>b</p>', 'My report');
    const a = htmlToPdf(html, { createdAt: '2026-09-25T12:00:00Z' });
    const b = htmlToPdf(html, { createdAt: '2026-09-25T12:00:00Z' });
    expect(a.equals(b)).toBe(true);
    const raw = a.toString('latin1');
    expect(raw).toContain('/Type /Outlines');
    expect((raw.match(/\/Title <feff/g) ?? []).length).toBe(3); // the document title and two bookmarks
    expect(raw).toContain('/CreationDate (D:20260925120000Z)');
    expect(raw).toContain('/DisplayDocTitle true');
  });
});

describe('htmlToPdf: what gets onto the page', () => {
  it('draws the visible text and leaves out what the web page hides: the filter rows, the skip link, the controls', () => {
    const { text } = readPdf(
      htmlToPdf(
        wrapHtml(
          `<a class="skip-link" href="#main">Skip to content</a><input type="checkbox" id="filter-all" /><label for="filter-all" class="filter-label">Show everything</label>
           <table><thead><tr><th>Id</th><th>State</th></tr></thead><tbody>
           <tr><td>SHOWN-ROW</td><td>yes</td></tr>
           <tr class="hideable default-hidden"><td>HIDDEN-ROW</td><td>no</td></tr></tbody></table>
           <ul><li class="hideable default-hidden">HIDDEN-ITEM</li><li>SHOWN-ITEM</li></ul><style>.x{}</style><script>SCRIPT-BODY</script>`,
        ),
      ),
    );
    expect(text).toContain('SHOWN-ROW');
    expect(text).toContain('SHOWN-ITEM');
    for (const gone of ['HIDDEN-ROW', 'HIDDEN-ITEM', 'Skip to content', 'Show everything', 'SCRIPT-BODY', '.x{}']) expect(text, gone).not.toContain(gone);
  });

  it('opens every collapsed section, with its title, because a printed page has nothing to click', () => {
    const { text } = readPdf(htmlToPdf(wrapHtml('<details><summary>Closed chapter</summary><p>Inside the closed chapter</p></details>')));
    expect(text).toContain('Closed chapter');
    expect(text).toContain('Inside the closed chapter');
  });

  it('decodes character references and keeps accented letters and typographic punctuation', () => {
    const { text } = readPdf(htmlToPdf(wrapHtml('<p>Zo&#235; &amp; caf&#233; &mdash; &ldquo;quoted&rdquo; &lt;b&gt; 5 &gt;= 3 → done</p>')));
    expect(text).toContain('Zoë & café — “quoted” <b> 5 >= 3 -> done');
  });

  it('drops emoji (each status badge also carries its word) and prints any other missing character as a question mark, never a wrong letter', () => {
    const { text } = readPdf(htmlToPdf(wrapHtml('<p><span class="badge status-pass">✅ Pass</span> <span class="badge status-fail">❌ Fail</span> 日本</p>')));
    expect(text).toContain('Pass');
    expect(text).toContain('Fail');
    expect(text).not.toMatch(/[✅❌]/);
    expect(text).toContain('??');
    expect(fullyRepresentable('Café — “ok” ✅')).toBe(true);
    expect(fullyRepresentable('日本')).toBe(false);
  });

  it('never runs text off the page: a path longer than the line is cut, at a slash where there is one', () => {
    const long = `/very/long/${'segment-'.repeat(40)}end`;
    const pdf = readPdf(htmlToPdf(wrapHtml(`<p>${long}</p><pre>${'x'.repeat(400)}</pre>`)));
    for (const o of pdf.ops) expect(o.x + textWidth(o.text, o.font as 'F1', o.size), o.text.slice(0, 30)).toBeLessThanOrEqual(595.28 - 48 + 0.5);
    expect(pdf.ops.map((o) => o.text).join('').replace(/\s/g, '')).toContain(long.replace(/\s/g, ''));
  });
});

describe('htmlToPdf: pages', () => {
  const rows = Array.from({ length: 120 }, (_, i) => `<tr><td>ROW-${i}</td><td>value ${i}</td></tr>`).join('');

  it('repeats a table header at the top of every page the table continues onto', () => {
    const pdf = readPdf(htmlToPdf(wrapHtml(`<h2>Big table</h2><table><thead><tr><th>HEADER-ONE</th><th>HEADER-TWO</th></tr></thead><tbody>${rows}</tbody></table>`)));
    expect(pdf.pageCount).toBeGreaterThan(2);
    for (let page = 1; page <= pdf.pageCount; page++) {
      expect(pdf.ops.some((o) => o.page === page && o.text === 'HEADER-ONE'), `page ${page}`).toBe(true);
    }
    for (let i = 0; i < 120; i++) expect(pdf.text, `ROW-${i}`).toContain(`ROW-${i}`);
  });

  it('splits one very tall table row across pages without losing a word of it', () => {
    const words = Array.from({ length: 4000 }, (_, i) => `w${i}`);
    const pdf = readPdf(htmlToPdf(wrapHtml(`<table><tr><td>${words.join(' ')}</td><td>side</td></tr></table>`)));
    expect(pdf.pageCount).toBeGreaterThan(1);
    const drawn = new Set(pdf.text.split(/\s+/));
    for (const w of words) expect(drawn.has(w), w).toBe(true);
  });

  it('keeps a heading with the block after it rather than leaving it alone at the foot of a page', () => {
    // Slide the heading through every position near the foot of the first page: at some of them, without the rule,
    // the heading would be the last thing on the page and its paragraph the first on the next.
    let stranded = 0;
    for (let n = 28; n <= 42; n++) {
      const filler = Array.from({ length: n }, (_, i) => `<p>filler line ${i}</p>`).join('');
      const pdf = readPdf(htmlToPdf(wrapHtml(`${filler}<h3>LONELY-HEADING</h3><p>${'body words '.repeat(60)}</p>`)));
      const heading = pdf.ops.find((o) => o.text === 'LONELY-HEADING')!;
      const after = pdf.ops.find((o) => o.text.startsWith('body words'))!;
      if (heading.page !== after.page) stranded++;
      if (heading.page === 1) expect(after.page, `${n} fillers`).toBe(1);
    }
    expect(stranded, 'the heading moves to the next page with its paragraph, at every position').toBe(0);
  });

  it('sets a table with many columns in smaller type rather than breaking the words in its cells', () => {
    const word = 'abcdefghijklm';
    const cells = (tag: string) => Array.from({ length: 9 }, () => `<${tag}>${word}</${tag}>`).join('');
    const pdf = readPdf(htmlToPdf(wrapHtml(`<table><thead><tr>${cells('th')}</tr></thead><tbody><tr>${cells('td')}</tr></tbody></table>`)));
    const printed = pdf.ops.filter((o) => o.text === word);
    expect(printed.length).toBe(18);
    expect(new Set(printed.map((o) => o.size)).size).toBe(1);
    expect(printed[0]!.size).toBeLessThan(8.5);
  });

  it('puts "Page n of N" and the title at the foot of every page', () => {
    const pdf = readPdf(htmlToPdf(wrapHtml(`<table><thead><tr><th>H</th></tr></thead><tbody>${rows}</tbody></table>`, 'Foot title')));
    for (let page = 1; page <= pdf.pageCount; page++) {
      expect(pdf.ops.some((o) => o.page === page && o.text === `Page ${page} of ${pdf.pageCount}`), `page ${page}`).toBe(true);
      expect(pdf.ops.some((o) => o.page === page && o.text === 'Foot title')).toBe(true);
    }
  });
});

describe('htmlToPdf: the real reports', () => {
  let dir: string;
  let model: ReportModel;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securevibe-pdf-'));
    model = await buildReportModel(join(dir, 'reports'), join(dir, 'app'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function reports(): [string, string][] {
    return [
      ['overview', renderOverview(model)],
      ['compliance report', renderComplianceReport(model).html],
      ['security report', renderSecurityReport(model).html],
      ['going-online checklist', renderGoingOnline(model).html],
    ];
  }

  it('lays out every report inside the margins, with every heading and the app name present', () => {
    for (const [name, html] of reports()) {
      const pdf = readPdf(htmlToPdf(html));
      expect(pdf.pageCount, name).toBeGreaterThan(0);
      for (const o of pdf.ops) expect(o.x + textWidth(o.text, o.font as 'F1', o.size), `${name}: ${o.text.slice(0, 30)}`).toBeLessThanOrEqual(595.28 - 48 + 0.5);
      for (const h of html.matchAll(/<h2>([^<]+)<\/h2>/g)) {
        const heading = decodeEntities(h[1]!);
        expect(pdf.text, `${name}: ${heading}`).toContain(heading.split(' ')[0]!);
      }
      expect(pdf.text, name).toContain(model.project.name);
    }
  });

  it('shows every status word the web page shows, none replaced by a placeholder', () => {
    for (const [name, html] of reports()) {
      // Rows the web page hides until asked ("not applicable", "out of level") are not printed either.
      const shown = cutOut(html, HIDDEN_ROWS);
      const text = readPdf(htmlToPdf(html)).text;
      const words = new Set([...shown.matchAll(/<span class="badge [^"]*">[^<\w]*([^<]+)<\/span>/g)].map((m) => m[1]!.trim()));
      expect(words.size, `${name} should have badges to compare`).toBeGreaterThanOrEqual(name === 'going-online checklist' ? 0 : 1);
      for (const badge of words) expect(text, `${name}: ${badge}`).toContain(badge);
    }
  });

  it('prints every ordinary word whole: no short word of the web page is broken across two lines of the PDF', () => {
    for (const [name, html] of reports()) {
      const shown = webPageText(html, { withPre: false });
      // A name may be carried over a line end after a hyphen, slash or underscore; nowhere else.
      const printed = new Set(readPdf(htmlToPdf(html)).text.replace(/(\S[-/_])\n/g, '$1').split(/\s+/));
      const broken = [...new Set(shown.split(/\s+/).filter((w) => w.length >= 3 && w.length <= 14 && /^[\x21-\x7e]+$/.test(w)))].filter((w) => !printed.has(w));
      expect(broken.slice(0, 10), name).toEqual([]);
    }
  });

  it('needs no character the fonts lack: nothing in the fixture reports would print as a question mark', () => {
    for (const [name, html] of reports()) {
      const visible = webPageText(html);
      const missing = [...new Set([...visible].filter((c) => !fullyRepresentable(c)))];
      expect(missing, name).toEqual([]);
    }
  });
});
