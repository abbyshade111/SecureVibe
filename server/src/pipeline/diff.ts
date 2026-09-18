/**
 * A small in-house unified diff, used to show what the fix agent actually changed (DESIGN §13 item 11) without
 * depending on the `diff` npm package or a `git` binary. Good enough for the generated app's source files: a
 * classic LCS line diff with three lines of context, formatted like `diff -u`.
 */

interface Hunk {
  aStart: number;
  aLines: number;
  bStart: number;
  bLines: number;
  lines: string[]; // ' ' / '-' / '+' prefixed
}

function splitLines(text: string): string[] {
  return text.length === 0 ? [] : text.split('\n');
}

/** Longest common subsequence of two line arrays, returned as the index pairs that match (in order). */
function lcsPairs(a: string[], b: string[]): [number, number][] {
  const n = a.length;
  const m = b.length;
  // dp[i][j] = LCS length of a[i..], b[j..]
  const dp: Uint32Array[] = new Array(n + 1);
  for (let i = 0; i <= n; i++) dp[i] = new Uint32Array(m + 1);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i]![j] = a[i] === b[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  const pairs: [number, number][] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      pairs.push([i, j]);
      i++;
      j++;
    } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
      i++;
    } else {
      j++;
    }
  }
  return pairs;
}

/** Builds a plain diff opcode list (' '=equal, '-'=only in a, '+'=only in b) from the LCS. */
function diffOpcodes(a: string[], b: string[]): { op: ' ' | '-' | '+'; text: string }[] {
  const pairs = lcsPairs(a, b);
  const ops: { op: ' ' | '-' | '+'; text: string }[] = [];
  let ai = 0;
  let bi = 0;
  for (const [pa, pb] of pairs) {
    while (ai < pa) ops.push({ op: '-', text: a[ai++]! });
    while (bi < pb) ops.push({ op: '+', text: b[bi++]! });
    ops.push({ op: ' ', text: a[ai]! });
    ai++;
    bi++;
  }
  while (ai < a.length) ops.push({ op: '-', text: a[ai++]! });
  while (bi < b.length) ops.push({ op: '+', text: b[bi++]! });
  return ops;
}

const CONTEXT = 3;
const MAX_LINES = 4000;

/** Renders a `diff -u`-style patch. Empty string when the two texts are identical. */
export function unifiedDiff(pathLabel: string, before: string, after: string): string {
  if (before === after) return '';
  const a = splitLines(before).slice(0, MAX_LINES);
  const b = splitLines(after).slice(0, MAX_LINES);
  const ops = diffOpcodes(a, b);

  const hunks: Hunk[] = [];
  let ai = 0;
  let bi = 0;
  let i = 0;
  while (i < ops.length) {
    if (ops[i]!.op === ' ') {
      ai++;
      bi++;
      i++;
      continue;
    }
    // Start of a change block: back up to include leading context.
    let start = i;
    const contextStart = Math.max(0, start - CONTEXT);
    const aStart = ai - (start - contextStart);
    const bStart = bi - (start - contextStart);
    let cursor = contextStart;
    let cai = aStart;
    let cbi = bStart;
    const lines: string[] = [];
    let trailingEqual = 0;
    while (cursor < ops.length) {
      const op = ops[cursor]!;
      if (op.op === ' ') {
        trailingEqual++;
        if (trailingEqual > CONTEXT * 2) break; // far enough past the last change; end the hunk
      } else {
        trailingEqual = 0;
      }
      lines.push(`${op.op}${op.text}`);
      if (op.op !== '+') cai++;
      if (op.op !== '-') cbi++;
      cursor++;
    }
    // Trim trailing context down to CONTEXT lines.
    let trimEnd = lines.length;
    let trailing = 0;
    while (trimEnd > 0 && lines[trimEnd - 1]!.startsWith(' ')) {
      trailing++;
      trimEnd--;
      if (trailing === CONTEXT) break;
    }
    const kept = lines.slice(0, trimEnd + Math.min(trailing, CONTEXT));
    const aLines = kept.filter((l) => l[0] !== '+').length;
    const bLines = kept.filter((l) => l[0] !== '-').length;
    hunks.push({ aStart: aStart + 1, aLines, bStart: bStart + 1, bLines, lines: kept });

    ai = cai;
    bi = cbi;
    i = cursor;
    start = i;
  }

  if (hunks.length === 0) return '';
  const header = [`--- a/${pathLabel}`, `+++ b/${pathLabel}`];
  const body = hunks.flatMap((h) => [`@@ -${h.aStart},${h.aLines} +${h.bStart},${h.bLines} @@`, ...h.lines]);
  return [...header, ...body].join('\n') + '\n';
}
