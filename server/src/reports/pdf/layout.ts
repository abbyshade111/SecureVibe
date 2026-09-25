/**
 * Turns the parsed report HTML into pages. The model is deliberately plain: every block becomes one or more "atoms"
 * (a run of wrapped lines, a table row, a spacer) with a known height; pages are filled atom by atom, splitting an
 * atom across a page break only where it can be split (lines of text, the cells of a table row). Boxes (banners,
 * finding cards) are not drawn as boxes but as a tint and a left bar behind each of their atoms, which stays
 * continuous across a page break.
 */
import { classesOf, textOf, type HtmlNode } from './html.js';
import { encode, hex, textWidth, type FontKey } from './fonts.js';
import { PAGE_HEIGHT, PAGE_WIDTH, type OutlineEntry, type PageLink, type PdfPage } from './writer.js';

const MARGIN_X = 48;
const TOP = 52;
const BOTTOM = PAGE_HEIGHT - 60;
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN_X;
const BODY = 10;
const CELL = 8.5;
const LEADING = 1.36;

const DARK = '0.10 0.11 0.13';
const MUTED = '0.29 0.32 0.36';
const LINK = '0.04 0.34 0.82';
const GOOD = '0.04 0.48 0.24';
const BAD = '0.70 0.15 0.12';
const WARN = '0.54 0.35 0';
const ORANGE = '0.60 0.30 0';
const INFO = '0.17 0.23 0.56';
const NEUTRAL = '0.36 0.40 0.44';
const PANEL = '0.965 0.973 0.98';
const BORDER = '0.79 0.82 0.85';

interface Style {
  font: FontKey;
  size: number;
  color: string;
  underline?: boolean;
  link?: string;
}

interface Deco {
  x: number;
  w: number;
  bg?: string;
  bar?: string;
}

interface Gfx {
  text(x: number, baseline: number, text: string, style: Style): void;
  rect(x: number, y: number, w: number, h: number, fill: string): void;
  frame(x: number, y: number, w: number, h: number): void;
  link(x: number, y: number, w: number, h: number, uri: string): void;
}

interface Atom {
  x: number;
  width: number;
  height: number;
  decos?: Deco[];
  keepNext?: boolean;
  /** How much of this atom must fit for it to be worth starting on the current page. */
  minHeight?: number;
  marker?: string;
  outline?: string;
  rule?: boolean;
  firstBase?: number;
  tableId?: number;
  header?: Atom;
  draw(g: Gfx, ox: number, y: number): void;
  split?(avail: number): [Atom, Atom] | null;
}

interface Ctx {
  x: number;
  width: number;
  style: Style;
  decos: Deco[];
  tight: boolean;
}

// ---------------------------------------------------------------------------------------------------- inline text

interface Tok {
  text?: string;
  br?: boolean;
  space: boolean;
  style: Style;
}

interface PlacedRun {
  text: string;
  x: number;
  style: Style;
}

interface Line {
  runs: PlacedRun[];
  h: number;
  base: number;
}

function bold(s: Style): Style {
  return { ...s, font: s.font === 'F3' || s.font === 'F4' ? 'F4' : s.font === 'F5' ? 'F5' : 'F2' };
}
function italic(s: Style): Style {
  return { ...s, font: s.font === 'F2' || s.font === 'F4' ? 'F4' : s.font === 'F5' ? 'F5' : 'F3' };
}

const BADGE: Record<string, string> = {
  'status-pass': GOOD, 'rating-good': GOOD, 'sbd-yes': GOOD,
  'status-fail': BAD, 'rating-at-risk': BAD, 'sbd-no': BAD, 'priority-P1': BAD,
  'status-partial': WARN, 'rating-needs-attention': WARN, 'status-not-verified': WARN, 'priority-P3': WARN,
  'priority-P2': ORANGE,
  'status-ai-assessed': INFO, 'status-documented': INFO, 'status-attested': INFO,
  'status-not-applicable': NEUTRAL, 'status-out-of-level': NEUTRAL, 'sbd-n-a': NEUTRAL, 'priority-P4': NEUTRAL,
};

function elementStyle(node: HtmlNode, s: Style): Style {
  let out = s;
  if (node.tag === 'strong' || node.tag === 'b') out = bold(out);
  if (node.tag === 'em' || node.tag === 'i') out = italic(out);
  if (node.tag === 'code') out = { ...out, font: 'F5', size: out.size * 0.92 };
  if (node.tag === 'a') {
    out = { ...out, color: LINK, underline: true };
    const href = node.attrs['href'] ?? '';
    if (/^https?:\/\//i.test(href)) out = { ...out, link: href };
  }
  for (const c of classesOf(node)) {
    if (BADGE[c]) out = bold({ ...out, color: BADGE[c]! });
    if (c === 'muted') out = { ...out, color: MUTED };
    if (c === 'critical-flag') out = bold({ ...out, color: BAD });
    if (c === 'n') out = bold({ ...out, size: out.size + 5 });
  }
  return out;
}

const INLINE = new Set(['a', 'span', 'strong', 'b', 'em', 'i', 'code', 'small', 'abbr', 'sup', 'sub', 'mark', 'br', 'kbd', 'q', 'cite']);

function hidden(node: HtmlNode): boolean {
  if (['style', 'script', 'head', 'title', 'meta', 'link', 'input', 'label', 'template'].includes(node.tag)) return true;
  const c = classesOf(node);
  return c.includes('skip-link') || c.includes('filter-label') || c.includes('filter-toggle') || (c.includes('hideable') && c.includes('default-hidden'));
}

interface InlineState {
  toks: Tok[];
  space: boolean;
}

function collect(nodes: (HtmlNode | string)[], style: Style, st: InlineState): void {
  for (const node of nodes) {
    if (typeof node === 'string') {
      for (const part of node.split(/(\s+)/)) {
        if (part === '') continue;
        if (/^\s+$/.test(part)) st.space = true;
        else if (encode(part).length === 0) continue; // an emoji on its own: nothing to draw, and no gap left behind
        else {
          st.toks.push({ text: part, style, space: st.space });
          st.space = false;
        }
      }
      continue;
    }
    if (hidden(node)) continue;
    if (node.tag === 'br') {
      st.toks.push({ br: true, space: false, style });
      st.space = false;
      continue;
    }
    collect(node.children, elementStyle(node, style), st);
    if (classesOf(node).includes('n')) st.toks.push({ br: true, space: false, style });
  }
}

function wrap(toks: Tok[], width: number): Line[] {
  const lines: Line[] = [];
  let runs: PlacedRun[] = [];
  let x = 0;
  let size = 0;
  const finish = (fallback: number) => {
    const s = size || fallback;
    const h = s * LEADING;
    lines.push({ runs, h, base: (h - s) / 2 + s * 0.8 });
    runs = [];
    x = 0;
    size = 0;
  };
  const same = (a: Style, b: Style) => a.font === b.font && a.size === b.size && a.color === b.color && a.underline === b.underline && a.link === b.link;
  const put = (text: string, style: Style, gap: number) => {
    const w = textWidth(text, style.font, style.size);
    const last = runs[runs.length - 1];
    if (last && same(last.style, style) && gap > 0) last.text += ` ${text}`;
    else if (last && same(last.style, style) && gap === 0 && last.x + textWidth(last.text, last.style.font, last.style.size) === x) last.text += text;
    else runs.push({ text, x: x + gap, style });
    x += gap + w;
    size = Math.max(size, style.size);
  };
  for (const tok of toks) {
    if (tok.br) {
      finish(tok.style.size);
      continue;
    }
    const text = tok.text!;
    const w = textWidth(text, tok.style.font, tok.style.size);
    const prev = runs[runs.length - 1];
    let gap = runs.length > 0 && tok.space && prev ? textWidth(' ', prev.style.font, prev.style.size) : 0;
    if (runs.length > 0 && x + gap + w > width) {
      finish(tok.style.size);
      gap = 0;
    }
    if (w <= width) {
      put(text, tok.style, gap);
      continue;
    }
    // A word longer than the line (a path, a hash): cut it where it runs out.
    let piece = '';
    for (const ch of text) {
      if (piece !== '' && x + gap + textWidth(piece + ch, tok.style.font, tok.style.size) > width) {
        // Cut after a hyphen, slash, underscore or dot when there is one, so names break where they read naturally.
        const cut = Math.max(piece.lastIndexOf('-'), piece.lastIndexOf('/'), piece.lastIndexOf('_'), piece.lastIndexOf('.'));
        const keep = cut > 0 && cut < piece.length - 1 ? cut + 1 : piece.length;
        put(piece.slice(0, keep), tok.style, gap);
        finish(tok.style.size);
        gap = 0;
        piece = piece.slice(keep);
      }
      piece += ch;
    }
    if (piece) put(piece, tok.style, gap);
  }
  if (runs.length > 0) finish(BODY);
  return lines;
}

function linesAtom(lines: Line[], x: number, width: number, before: number, after: number, decos: Deco[]): Atom {
  const total = (ls: Line[]) => ls.reduce((n, l) => n + l.h, 0);
  const build = (ls: Line[], b: number, a: number): Atom => ({
    x,
    width,
    height: b + total(ls) + a,
    decos,
    firstBase: b + (ls[0]?.base ?? BODY),
    minHeight: b + Math.min(total(ls), (ls[0]?.h ?? 0) * 2),
    draw(g, ox, y) {
      let top = y + b;
      for (const line of ls) {
        for (const run of line.runs) {
          g.text(ox + x + run.x, top + line.base, run.text, run.style);
          const w = textWidth(run.text, run.style.font, run.style.size);
          if (run.style.underline) g.rect(ox + x + run.x, top + line.base + 1.4, w, 0.5, run.style.color);
          if (run.style.link) g.link(ox + x + run.x, top, w, line.h, run.style.link);
        }
        top += line.h;
      }
    },
    split(avail) {
      if (ls.length < 4) return null;
      let used = b;
      let k = 0;
      while (k < ls.length && used + ls[k]!.h <= avail) used += ls[k++]!.h;
      k = Math.min(k, ls.length - 2);
      if (k < 2) return null;
      return [build(ls.slice(0, k), b, 0), build(ls.slice(k), 0, a)];
    },
  });
  return build(lines, before, after);
}

function paragraph(nodes: (HtmlNode | string)[], ctx: Ctx, before: number, after: number, style = ctx.style): Atom | undefined {
  const st: InlineState = { toks: [], space: false };
  collect(nodes, style, st);
  const lines = wrap(st.toks, ctx.width);
  if (lines.length === 0) return undefined;
  return linesAtom(lines, ctx.x, ctx.width, before, after, ctx.decos);
}

function spacer(ctx: Ctx, height: number, decos = ctx.decos): Atom {
  return { x: ctx.x, width: ctx.width, height, decos, draw() {} };
}

// ----------------------------------------------------------------------------------------------------- tables

interface Cell {
  x: number;
  w: number;
  atoms: Atom[];
}

const PAD = 4;
let tableSeq = 0;

function stackHeight(atoms: Atom[]): number {
  return atoms.reduce((n, a) => n + a.height, 0);
}

/** The atoms of a cell that fit in `avail`, and what is left over (splitting one atom if it can be split). */
function splitStack(atoms: Atom[], avail: number): [Atom[], Atom[]] {
  const head: Atom[] = [];
  let used = 0;
  for (let i = 0; i < atoms.length; i++) {
    const a = atoms[i]!;
    if (used + a.height <= avail) {
      head.push(a);
      used += a.height;
      continue;
    }
    const parts = a.split?.(avail - used);
    if (parts) return [[...head, parts[0]], [parts[1], ...atoms.slice(i + 1)]];
    return [head, atoms.slice(i)];
  }
  return [head, []];
}

function rowAtom(cells: Cell[], x: number, width: number, opts: { header: boolean; borders: boolean; tableId?: number; head?: Atom }): Atom {
  const pad = opts.borders ? PAD : 0;
  const height = Math.max(...cells.map((c) => stackHeight(c.atoms)), 0) + 2 * pad;
  const atom: Atom = {
    x,
    width,
    height,
    keepNext: opts.header,
    tableId: opts.tableId,
    header: opts.head,
    draw(g, ox, y) {
      for (const cell of cells) {
        if (opts.header) g.rect(ox + x + cell.x, y, cell.w, height, PANEL);
        if (opts.borders) g.frame(ox + x + cell.x, y, cell.w, height);
        let top = y + pad;
        for (const a of cell.atoms) {
          a.draw(g, ox + x + cell.x + pad, top);
          top += a.height;
        }
      }
    },
    split(avail) {
      const room = avail - 2 * pad;
      if (room < 12) return null;
      const heads: Cell[] = [];
      const rests: Cell[] = [];
      for (const cell of cells) {
        const [h, r] = splitStack(cell.atoms, room);
        heads.push({ ...cell, atoms: h });
        rests.push({ ...cell, atoms: r });
      }
      if (heads.every((c) => c.atoms.length === 0) || rests.every((c) => c.atoms.length === 0)) return null;
      return [
        rowAtom(heads, x, width, { ...opts, header: opts.header }),
        rowAtom(rests, x, width, { ...opts, header: false, head: opts.head }),
      ];
    },
  };
  return atom;
}

function cellStyle(header: boolean, size = CELL): Style {
  return { font: header ? 'F2' : 'F1', size, color: DARK };
}

/** True when part of a cell is drawn bold (a badge, a strong word), which is wider than the plain font it is measured in. */
function hasBold(node: HtmlNode): boolean {
  if (node.tag === 'strong' || node.tag === 'b' || classesOf(node).some((c) => BADGE[c] || c === 'critical-flag' || c === 'n')) return true;
  return node.children.some((c) => typeof c !== 'string' && hasBold(c));
}

function layoutTable(node: HtmlNode, ctx: Ctx): Atom[] {
  const rows: { cells: HtmlNode[]; header: boolean }[] = [];
  const walk = (n: HtmlNode, inHead: boolean) => {
    for (const child of n.children) {
      if (typeof child === 'string' || hidden(child)) continue;
      if (child.tag === 'tr') {
        const cells = child.children.filter((c): c is HtmlNode => typeof c !== 'string' && (c.tag === 'td' || c.tag === 'th'));
        if (cells.length > 0) rows.push({ cells, header: inHead || cells.every((c) => c.tag === 'th') });
      } else if (['thead', 'tbody', 'tfoot'].includes(child.tag)) walk(child, child.tag === 'thead');
    }
  };
  walk(node, false);
  if (rows.length === 0) return [];
  const cols = Math.max(...rows.map((r) => r.cells.length));
  // A wide table is set in smaller type before any word in it is broken: the largest size at which every column
  // can hold its longest word is used, and only a table that cannot fit even at the smallest size breaks words.
  const measure = (size: number) => {
    const maxW = new Array<number>(cols).fill(0);
    const minW = new Array<number>(cols).fill(0);
    for (const row of rows) {
      row.cells.forEach((cell, i) => {
        const s = cellStyle(row.header || cell.tag === 'th' || hasBold(cell), size);
        for (const line of textOf(cell).split('\n')) {
          maxW[i] = Math.max(maxW[i]!, textWidth(line.trim(), s.font, s.size));
          for (const word of line.split(/\s+/)) minW[i] = Math.max(minW[i]!, textWidth(word, s.font, s.size));
        }
      });
    }
    return { want: maxW.map((w) => w + 2 * PAD + 1), least: minW.map((w) => Math.min(w, 90) + 2 * PAD + 1) };
  };
  let size = CELL;
  let { want, least } = measure(size);
  for (const smaller of [8, 7.5, 7]) {
    if (least.reduce((a, b) => a + b, 0) <= ctx.width) break;
    size = smaller;
    ({ want, least } = measure(size));
  }
  const sumWant = want.reduce((a, b) => a + b, 0);
  const sumLeast = least.reduce((a, b) => a + b, 0);
  let widths: number[];
  if (sumWant <= ctx.width) widths = want.map((w) => w + ((ctx.width - sumWant) * w) / sumWant);
  else if (sumLeast >= ctx.width) {
    // Too many words that must not break: shrink the longest ones first, and only then the short ones.
    const floor = least.map((w) => Math.min(w, 46));
    const sumFloor = floor.reduce((a, b) => a + b, 0);
    widths =
      sumFloor >= ctx.width
        ? least.map((w) => (w * ctx.width) / sumLeast)
        : least.map((w, i) => floor[i]! + ((w - floor[i]!) * (ctx.width - sumFloor)) / (sumLeast - sumFloor));
  }
  else {
    const spare = want.map((w, i) => w - least[i]!);
    const sumSpare = spare.reduce((a, b) => a + b, 0);
    widths = least.map((w, i) => w + ((ctx.width - sumLeast) * spare[i]!) / sumSpare);
  }
  const id = ++tableSeq;
  let head: Atom | undefined;
  const atoms: Atom[] = [];
  for (const row of rows) {
    let at = 0;
    const cells: Cell[] = row.cells.map((cell, i) => {
      const w = widths[i]!;
      const cellCtx: Ctx = { x: 0, width: w - 2 * PAD, style: cellStyle(row.header || cell.tag === 'th', size), decos: [], tight: true };
      const c: Cell = { x: at, w, atoms: layoutChildren(cell.children, cellCtx) };
      at += w;
      return c;
    });
    const atom = rowAtom(cells, ctx.x, ctx.width, { header: row.header, borders: true, tableId: id, head });
    atom.decos = ctx.decos;
    if (row.header && !head) head = atom;
    atoms.push(atom);
  }
  atoms.push(spacer(ctx, 6));
  return atoms;
}

/** A row of equal boxes (the scorecards) or a label and its value (a definition list), built from child nodes. */
function layoutRow(groups: (HtmlNode | string)[][], widths: number[], ctx: Ctx, borders: boolean, styles: Style[]): Atom {
  let at = 0;
  const cells = groups.map((nodes, i) => {
    const w = widths[i]!;
    const inner = borders ? PAD : 0;
    const cellCtx: Ctx = { x: 0, width: w - 2 * inner - (borders ? 0 : 6), style: styles[i]!, decos: [], tight: true };
    const c: Cell = { x: at, w, atoms: layoutChildren(nodes, cellCtx) };
    at += w;
    return c;
  });
  const atom = rowAtom(cells, ctx.x, ctx.width, { header: false, borders });
  atom.decos = ctx.decos;
  return atom;
}

// ------------------------------------------------------------------------------------------------------ blocks

const HEADINGS: Record<string, { size: number; before: number; after: number }> = {
  h1: { size: 20, before: 0, after: 4 },
  h2: { size: 15, before: 16, after: 8 },
  h3: { size: 12.5, before: 10, after: 4 },
  h4: { size: 11, before: 8, after: 3 },
  h5: { size: 10.5, before: 6, after: 2 },
  h6: { size: 10, before: 6, after: 2 },
};

const BOXES: Record<string, { bg: string; bar: string }> = {
  'banner-ai-disclaimer': { bg: '1 0.957 0.898', bar: '0.878 0.639 0' },
  'banner-preview': { bg: '0.933 0.949 1', bar: '0.416 0.482 0.839' },
  'banner-note': { bg: PANEL, bar: BORDER },
  'finding-card': { bg: PANEL, bar: BORDER },
  adr: { bg: PANEL, bar: BORDER },
  toc: { bg: PANEL, bar: BORDER },
};

function layoutChildren(children: (HtmlNode | string)[], ctx: Ctx): Atom[] {
  const out: Atom[] = [];
  let buffer: (HtmlNode | string)[] = [];
  const flush = () => {
    if (buffer.length === 0) return;
    const p = paragraph(buffer, ctx, 0, ctx.tight ? 1 : 4);
    if (p) out.push(p);
    buffer = [];
  };
  for (const child of children) {
    if (typeof child === 'string' || (INLINE.has(child.tag) && !hidden(child))) {
      buffer.push(child);
      continue;
    }
    if (hidden(child)) continue;
    flush();
    layoutBlock(child, ctx, out);
  }
  flush();
  return out;
}

function layoutBlock(node: HtmlNode, ctx: Ctx, out: Atom[]): void {
  const classes = classesOf(node);
  const heading = HEADINGS[node.tag];
  if (heading) {
    const style = bold({ font: 'F1', size: heading.size, color: DARK });
    const a = paragraph(node.children, ctx, ctx.tight ? 2 : heading.before, ctx.tight ? 2 : heading.after, style);
    if (a) {
      a.keepNext = true;
      if (node.tag === 'h2') {
        a.outline = textOf(node).trim();
        a.rule = true;
      }
      out.push(a);
    }
    return;
  }
  switch (node.tag) {
    case 'p': {
      const a = paragraph(node.children, ctx, 0, ctx.tight ? 1 : 6);
      if (a) out.push(a);
      return;
    }
    case 'hr':
      out.push({ x: ctx.x, width: ctx.width, height: 10, decos: ctx.decos, draw(g, ox, y) { g.rect(ox + ctx.x, y + 5, ctx.width, 0.6, BORDER); } });
      return;
    case 'pre': {
      const size = 8;
      const perLine = Math.max(10, Math.floor((ctx.width - 12) / (0.6 * size)));
      const lines: Line[] = [];
      for (const raw of textOf(node).replace(/\s+$/, '').split('\n')) {
        const text = raw.replace(/\t/g, '  ');
        for (let i = 0; i === 0 || i < text.length; i += perLine) {
          const style: Style = { font: 'F5', size, color: DARK };
          lines.push({ runs: [{ text: text.slice(i, i + perLine), x: 0, style }], h: size * 1.3, base: size * 1.05 });
        }
      }
      const deco: Deco = { x: ctx.x, w: ctx.width, bg: PANEL };
      out.push(linesAtom(lines, ctx.x + 6, ctx.width - 12, 6, 6, [...ctx.decos, deco]));
      out.push(spacer(ctx, 6));
      return;
    }
    case 'ul':
    case 'ol': {
      let n = 0;
      for (const li of node.children) {
        if (typeof li === 'string' || li.tag !== 'li' || hidden(li)) continue;
        n++;
        const atoms = layoutChildren(li.children, { ...ctx, x: ctx.x + 16, width: ctx.width - 16, tight: true });
        if (atoms.length === 0) continue;
        atoms[0]!.marker = node.tag === 'ol' ? `${n}.` : '•';
        const last = atoms[atoms.length - 1]!;
        if (last === atoms[0] && !ctx.tight) last.height += 2;
        out.push(...atoms);
      }
      out.push(spacer(ctx, ctx.tight ? 2 : 4));
      return;
    }
    case 'table':
      out.push(...layoutTable(node, ctx));
      return;
    case 'dl': {
      const kids = node.children.filter((c): c is HtmlNode => typeof c !== 'string' && !hidden(c));
      const labelW = Math.min(130, ctx.width * 0.3);
      for (let i = 0; i < kids.length; i++) {
        const dt = kids[i]!;
        if (dt.tag !== 'dt') continue;
        const dd = kids[i + 1]?.tag === 'dd' ? kids[i + 1]! : undefined;
        const styles: Style[] = [bold({ font: 'F1', size: BODY, color: MUTED }), { font: 'F1', size: BODY, color: DARK }];
        out.push(layoutRow([dt.children, dd?.children ?? []], [labelW, ctx.width - labelW], ctx, false, styles));
      }
      out.push(spacer(ctx, 4));
      return;
    }
    case 'details': {
      const summary = node.children.find((c): c is HtmlNode => typeof c !== 'string' && c.tag === 'summary');
      if (summary) {
        const a = paragraph(summary.children, ctx, ctx.tight ? 2 : 8, 3, bold({ ...ctx.style, size: 11, color: DARK }));
        if (a) {
          a.keepNext = true;
          out.push(a);
        }
      }
      out.push(...layoutChildren(node.children.filter((c) => c !== summary), ctx));
      return;
    }
    case 'summary':
      return;
  }
  if (classes.includes('scorecard')) {
    const cells = node.children.filter((c): c is HtmlNode => typeof c !== 'string' && !hidden(c));
    if (cells.length > 0) {
      const w = ctx.width / cells.length;
      out.push(layoutRow(cells.map((c) => c.children), cells.map(() => w), ctx, true, cells.map(() => ({ font: 'F1', size: BODY, color: DARK }))));
      out.push(spacer(ctx, 8));
    }
    return;
  }
  const boxName = classes.find((c) => BOXES[c]) ?? (node.tag === 'nav' && classes.includes('toc') ? 'toc' : undefined);
  if (boxName) {
    const box = BOXES[boxName]!;
    const pad = 8;
    const deco: Deco = { x: ctx.x, w: ctx.width, bg: box.bg, bar: box.bar };
    const inner: Ctx = { ...ctx, x: ctx.x + pad + 3, width: ctx.width - 2 * pad - 3, decos: [...ctx.decos, deco] };
    const style = boxName.startsWith('banner') ? bold(ctx.style) : ctx.style;
    const kids = layoutChildren(node.children, { ...inner, style });
    if (kids.length === 0) return;
    out.push(spacer(ctx, pad, inner.decos), ...kids, spacer(ctx, pad, inner.decos), spacer(ctx, 8));
    return;
  }
  // Any other container (section, div, header, main, footer, article, body, html): its children, in order.
  const style = node.tag === 'footer' ? { ...ctx.style, size: 8.5, color: MUTED } : ctx.style;
  out.push(...layoutChildren(node.children, { ...ctx, style }));
  if (node.tag === 'header' && classes.includes('report-header')) {
    out.push({ x: ctx.x, width: ctx.width, height: 14, decos: ctx.decos, draw(g, ox, y) { g.rect(ox + ctx.x, y + 5, ctx.width, 1.5, BORDER); } });
  }
}

// ---------------------------------------------------------------------------------------------------- pages

class Pager implements Gfx {
  pages: { ops: string[]; links: PageLink[] }[] = [];
  outline: OutlineEntry[] = [];
  y = TOP;
  lastTable: number | undefined;

  constructor() {
    this.newPage();
  }

  newPage(): void {
    this.pages.push({ ops: [], links: [] });
    this.y = TOP;
  }

  private get page() {
    return this.pages[this.pages.length - 1]!;
  }

  private num(n: number): string {
    return (Math.round(n * 100) / 100).toString();
  }

  text(x: number, baseline: number, text: string, style: Style): void {
    const bytes = encode(text);
    if (bytes.length === 0) return;
    this.page.ops.push(`BT /${style.font} ${this.num(style.size)} Tf ${style.color} rg ${this.num(x)} ${this.num(PAGE_HEIGHT - baseline)} Td <${hex(bytes)}> Tj ET`);
  }

  rect(x: number, y: number, w: number, h: number, fill: string): void {
    this.page.ops.push(`${fill} rg ${this.num(x)} ${this.num(PAGE_HEIGHT - y - h)} ${this.num(w)} ${this.num(h)} re f`);
  }

  frame(x: number, y: number, w: number, h: number): void {
    this.page.ops.push(`${BORDER} RG 0.5 w ${this.num(x)} ${this.num(PAGE_HEIGHT - y - h)} ${this.num(w)} ${this.num(h)} re S`);
  }

  link(x: number, y: number, w: number, h: number, uri: string): void {
    this.page.links.push({ x1: x, y1: PAGE_HEIGHT - y - h, x2: x + w, y2: PAGE_HEIGHT - y, uri });
  }

  place(a: Atom): void {
    const y = this.y;
    for (const d of a.decos ?? []) {
      if (d.bg) this.rect(d.x, y, d.w, a.height, d.bg);
      if (d.bar) this.rect(d.x, y, 3, a.height, d.bar);
    }
    if (a.marker) this.text(a.x - 12, y + (a.firstBase ?? 10), a.marker, { font: 'F1', size: BODY, color: DARK });
    if (a.outline) this.outline.push({ title: a.outline, page: this.pages.length - 1, y });
    a.draw(this, 0, y);
    if (a.rule) this.rect(a.x, y + a.height - 4, a.width, 0.8, BORDER);
    if (a.tableId !== undefined) this.lastTable = a.tableId;
    this.y += a.height;
  }
}

function paginate(atoms: Atom[], pager: Pager): void {
  const queue = [...atoms];
  while (queue.length > 0) {
    const a = queue.shift()!;
    const avail = BOTTOM - pager.y;
    const fresh = pager.y <= TOP + 0.5;
    if (a.keepNext && !fresh && queue.length > 0) {
      const next = queue[0]!;
      if (a.height + (next.minHeight ?? next.height) > avail) {
        pager.newPage();
        queue.unshift(a);
        continue;
      }
    }
    if (a.height <= avail + 0.01) {
      // A table that continues on a new page starts again with its header row.
      if (fresh && a.header && pager.lastTable === a.tableId && pager.pages.length > 1) pager.place(a.header);
      pager.place(a);
      continue;
    }
    const parts = a.split?.(avail);
    if (parts) {
      pager.place(parts[0]);
      pager.newPage();
      queue.unshift(parts[1]);
      continue;
    }
    if (!fresh) {
      pager.newPage();
      queue.unshift(a);
      continue;
    }
    pager.place(a); // taller than a page and cannot be split: draw it and let it run on
  }
}

export interface LaidOut {
  pages: PdfPage[];
  outline: OutlineEntry[];
}

export function layoutDocument(root: HtmlNode, title: string): LaidOut {
  const ctx: Ctx = { x: MARGIN_X, width: CONTENT_WIDTH, style: { font: 'F1', size: BODY, color: DARK }, decos: [], tight: false };
  const atoms = layoutChildren(root.children, ctx);
  const pager = new Pager();
  paginate(atoms, pager);
  const total = pager.pages.length;
  const footer: Style = { font: 'F1', size: 8, color: MUTED };
  const pages: PdfPage[] = pager.pages.map((p, i) => {
    const label = `Page ${i + 1} of ${total}`;
    const g = new Pager();
    g.pages = [p];
    g.text(MARGIN_X, PAGE_HEIGHT - 34, title.length > 90 ? `${title.slice(0, 89)}…` : title, footer);
    g.text(PAGE_WIDTH - MARGIN_X - textWidth(label, 'F1', 8), PAGE_HEIGHT - 34, label, footer);
    return { ops: p.ops.join('\n'), links: p.links };
  });
  return { pages, outline: pager.outline };
}
