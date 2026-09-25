/**
 * A small reader for the HTML SecureVibe writes itself (reports/page.ts and the section renderers): a fixed set of
 * tags, double-quoted attributes, no scripts. It is not a general HTML parser and does not try to be; the content it
 * does not know is skipped, never guessed at.
 */

export interface HtmlNode {
  tag: string;
  attrs: Record<string, string>;
  children: (HtmlNode | string)[];
}

const VOID = new Set(['br', 'hr', 'img', 'input', 'meta', 'link', 'wbr']);
const RAW = new Set(['style', 'script']);
/** Opening one of these closes an open element of the listed kind that sits directly above it. */
const AUTO_CLOSE: Record<string, string[]> = {
  li: ['li'],
  td: ['td', 'th'],
  th: ['td', 'th'],
  tr: ['tr', 'td', 'th'],
  dt: ['dt', 'dd'],
  dd: ['dt', 'dd'],
  thead: ['tbody', 'thead'],
  tbody: ['tbody', 'thead'],
};

const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•', middot: '·', rarr: '→',
  larr: '←', copy: '©', times: '×', ge: '≥', le: '≤',
};

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, body: string) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[body.toLowerCase()] ?? whole;
  });
}

function parseAttrs(source: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const m of source.matchAll(/([a-zA-Z_:][-\w:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
    attrs[m[1]!.toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  }
  return attrs;
}

export function parseHtml(source: string): HtmlNode {
  const root: HtmlNode = { tag: '#root', attrs: {}, children: [] };
  const stack: HtmlNode[] = [root];
  const top = () => stack[stack.length - 1]!;
  const pattern = /<!--[\s\S]*?-->|<!doctype[^>]*>|<(\/?)([a-zA-Z][a-zA-Z0-9-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/gi;
  let last = 0;
  for (let m = pattern.exec(source); m; m = pattern.exec(source)) {
    if (m.index > last) top().children.push(decodeEntities(source.slice(last, m.index)));
    last = pattern.lastIndex;
    if (m[2] === undefined) continue; // a comment or the doctype
    const tag = m[2].toLowerCase();
    if (m[1] === '/') {
      const at = stack.map((n) => n.tag).lastIndexOf(tag);
      if (at > 0) stack.length = at;
      continue;
    }
    const closes = AUTO_CLOSE[tag];
    while (closes && stack.length > 1 && closes.includes(top().tag)) stack.pop();
    const node: HtmlNode = { tag, attrs: parseAttrs(m[3] ?? ''), children: [] };
    top().children.push(node);
    if (RAW.has(tag)) {
      const end = source.toLowerCase().indexOf(`</${tag}`, last);
      const stop = end === -1 ? source.length : end;
      node.children.push(source.slice(last, stop));
      const close = source.indexOf('>', stop);
      last = pattern.lastIndex = close === -1 ? source.length : close + 1;
      continue;
    }
    if (!VOID.has(tag) && !/\/\s*$/.test(m[3] ?? '')) stack.push(node);
  }
  if (last < source.length) top().children.push(decodeEntities(source.slice(last)));
  return root;
}

export function classesOf(node: HtmlNode): string[] {
  return (node.attrs['class'] ?? '').split(/\s+/).filter(Boolean);
}

/** The text inside a node, blocks separated by newlines; used to measure and to name things. */
export function textOf(node: HtmlNode | string): string {
  if (typeof node === 'string') return node;
  if (node.tag === 'style' || node.tag === 'script') return '';
  const inner = node.children.map(textOf).join('');
  return ['p', 'div', 'li', 'tr', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'dt', 'dd', 'summary'].includes(node.tag) ? `${inner}\n` : inner;
}
