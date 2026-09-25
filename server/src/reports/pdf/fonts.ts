/**
 * The five fonts every PDF reader carries (Helvetica, its bold and oblique forms, and Courier), so a report needs no
 * font file. The price is the alphabet: these fonts hold Western European letters and common punctuation, nothing
 * else. `encode` says what happens to the rest: emoji and pictographs are dropped (every status in the reports is
 * also written as a word beside its icon), a few symbols become ASCII, and any other character becomes "?".
 */

export type FontKey = 'F1' | 'F2' | 'F3' | 'F4' | 'F5';

export const FONTS: Record<FontKey, string> = {
  F1: 'Helvetica',
  F2: 'Helvetica-Bold',
  F3: 'Helvetica-Oblique',
  F4: 'Helvetica-BoldOblique',
  F5: 'Courier',
};

// Advance widths in 1/1000 em for the characters 32..126, from the Adobe core-14 font metrics.
const HELVETICA = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
  278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667,
  611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833,
  556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];
const HELVETICA_BOLD = [
  278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
  333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667,
  611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889,
  611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

/** Widths of the WinAnsi bytes above 126 that differ noticeably from an average letter. */
const HIGH_WIDTHS: Record<number, [number, number]> = {
  0x85: [1000, 1000],
  0x91: [222, 278],
  0x92: [222, 278],
  0x93: [333, 500],
  0x94: [333, 500],
  0x95: [350, 350],
  0x96: [556, 556],
  0x97: [1000, 1000],
  0x99: [1000, 1000],
  0xa0: [278, 278],
  0xb7: [278, 333],
  0xd7: [584, 584],
};

/** The WinAnsi (Windows-1252) bytes 0x80..0x9F, which are not the same as the Unicode code points. */
const CP1252: Record<number, number> = {
  0x20ac: 0x80, 0x201a: 0x82, 0x0192: 0x83, 0x201e: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87, 0x02c6: 0x88, 0x2030: 0x89,
  0x0160: 0x8a, 0x2039: 0x8b, 0x0152: 0x8c, 0x017d: 0x8e, 0x2018: 0x91, 0x2019: 0x92, 0x201c: 0x93, 0x201d: 0x94, 0x2022: 0x95,
  0x2013: 0x96, 0x2014: 0x97, 0x02dc: 0x98, 0x2122: 0x99, 0x0161: 0x9a, 0x203a: 0x9b, 0x0153: 0x9c, 0x017e: 0x9e, 0x0178: 0x9f,
};

const ASCII_FOR: Record<number, string> = {
  0x2192: '->',
  0x2190: '<-',
  0x2265: '>=',
  0x2264: '<=',
  0x2011: '-',
  0x2010: '-',
  0x2012: '-',
  0x2212: '-',
  0x2032: "'",
  0x2033: '"',
};

function dropped(code: number): boolean {
  return (
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x2190 && code <= 0x21ff) ||
    (code >= 0x2300 && code <= 0x23ff) ||
    (code >= 0x2600 && code <= 0x27bf) ||
    (code >= 0x2b00 && code <= 0x2bff) ||
    (code >= 0xfe00 && code <= 0xfe0f) ||
    (code >= 0x1f000 && code <= 0x1ffff)
  );
}

/** The WinAnsi bytes for `text`. Pictographs vanish; characters the fonts lack become "?". */
export function encode(text: string): number[] {
  const out: number[] = [];
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code >= 32 && code <= 126) out.push(code);
    else if (code >= 0xa0 && code <= 0xff) out.push(code);
    else if (CP1252[code] !== undefined) out.push(CP1252[code]!);
    else if (code === 9 || code === 10 || code === 13) out.push(32);
    else if (ASCII_FOR[code] !== undefined) for (const c of ASCII_FOR[code]!) out.push(c.charCodeAt(0));
    else if (dropped(code)) continue;
    else if (code > 126) out.push(63);
  }
  return out;
}

/** True when every character of `text` survives `encode` as itself or as a deliberate replacement (not "?"). */
export function fullyRepresentable(text: string): boolean {
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code === 63) continue;
    if (code >= 32 && code <= 126) continue;
    if (code >= 0xa0 && code <= 0xff) continue;
    if (CP1252[code] !== undefined || ASCII_FOR[code] !== undefined || dropped(code) || code === 9 || code === 10 || code === 13) continue;
    if (code > 126) return false;
  }
  return true;
}

function byteWidth(byte: number, font: FontKey): number {
  if (font === 'F5') return 600;
  const bold = font === 'F2' || font === 'F4';
  if (byte >= 32 && byte <= 126) return (bold ? HELVETICA_BOLD : HELVETICA)[byte - 32]!;
  const special = HIGH_WIDTHS[byte];
  if (special) return special[bold ? 1 : 0];
  return bold ? 611 : 556;
}

export function textWidth(text: string, font: FontKey, size: number): number {
  let total = 0;
  for (const b of encode(text)) total += byteWidth(b, font);
  return (total * size) / 1000;
}

export function hex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}
