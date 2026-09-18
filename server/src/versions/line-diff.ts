/**
 * A small line diff (longest common subsequence) with unified output, for showing what changed between two
 * versions of an app. Dependency-free and bounded: very long files are compared on a prefix and marked truncated.
 */

export interface UnifiedDiff {
  text: string;
  linesAdded: number;
  linesRemoved: number;
  truncated: boolean;
}

/** Files longer than this (in lines) are diffed on their first MAX_LINES lines only. */
export const MAX_LINES = 4000;
const CONTEXT = 3;

type Op = { kind: ' ' | '+' | '-'; line: string };

function lcsOps(a: string[], b: string[]): Op[] {
  // Standard dynamic-programming LCS table; bounded by MAX_LINES so the table stays affordable.
  const n = a.length;
  const m = b.length;
  const table: Uint32Array[] = [];
  for (let i = 0; i <= n; i++) table.push(new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      table[i]![j] = a[i] === b[j] ? table[i + 1]![j + 1]! + 1 : Math.max(table[i + 1]![j]!, table[i]![j + 1]!);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ kind: ' ', line: a[i]! });
      i++;
      j++;
    } else if (table[i + 1]![j]! >= table[i]![j + 1]!) {
      ops.push({ kind: '-', line: a[i]! });
      i++;
    } else {
      ops.push({ kind: '+', line: b[j]! });
      j++;
    }
  }
  while (i < n) ops.push({ kind: '-', line: a[i++]! });
  while (j < m) ops.push({ kind: '+', line: b[j++]! });
  return ops;
}

export function unifiedDiff(before: string, after: string, label: string): UnifiedDiff {
  const splitLines = (text: string) => (text === '' ? [] : text.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n'));
  let a = splitLines(before);
  let b = splitLines(after);
  const truncated = a.length > MAX_LINES || b.length > MAX_LINES;
  if (truncated) {
    a = a.slice(0, MAX_LINES);
    b = b.slice(0, MAX_LINES);
  }
  const ops = lcsOps(a, b);
  let linesAdded = 0;
  let linesRemoved = 0;
  for (const op of ops) {
    if (op.kind === '+') linesAdded++;
    else if (op.kind === '-') linesRemoved++;
  }

  // Hunks: runs of changes with CONTEXT unchanged lines either side.
  const out: string[] = [`--- ${label} (before)`, `+++ ${label} (after)`];
  let oldLine = 1;
  let newLine = 1;
  let k = 0;
  while (k < ops.length) {
    if (ops[k]!.kind === ' ') {
      oldLine++;
      newLine++;
      k++;
      continue;
    }
    // Start of a hunk: back up for context.
    let start = k;
    let contextBefore = 0;
    while (start > 0 && contextBefore < CONTEXT && ops[start - 1]!.kind === ' ') {
      start--;
      contextBefore++;
    }
    let end = k;
    let sinceChange = 0;
    while (end < ops.length && sinceChange <= CONTEXT * 2) {
      if (ops[end]!.kind === ' ') sinceChange++;
      else sinceChange = 0;
      end++;
    }
    // Trim trailing context beyond CONTEXT lines.
    let trailing = 0;
    while (end > k && ops[end - 1]!.kind === ' ' && trailing < 0) end--;
    let e = end;
    let count = 0;
    while (e > k && ops[e - 1]!.kind === ' ') {
      e--;
      count++;
    }
    end = e + Math.min(count, CONTEXT);
    trailing = 0;

    const hunkOldStart = oldLine - contextBefore;
    const hunkNewStart = newLine - contextBefore;
    let oldCount = 0;
    let newCount = 0;
    const lines: string[] = [];
    for (let x = start; x < end; x++) {
      const op = ops[x]!;
      lines.push(`${op.kind}${op.line}`);
      if (op.kind !== '+') oldCount++;
      if (op.kind !== '-') newCount++;
    }
    out.push(`@@ -${hunkOldStart},${oldCount} +${hunkNewStart},${newCount} @@`, ...lines);
    // Advance the counters past the hunk.
    for (let x = k; x < end; x++) {
      const op = ops[x]!;
      if (op.kind !== '+') oldLine++;
      if (op.kind !== '-') newLine++;
    }
    k = end;
  }
  if (truncated) out.push(`@@ only the first ${MAX_LINES} lines were compared @@`);
  return { text: `${out.join('\n')}\n`, linesAdded, linesRemoved, truncated };
}

/** Line counts without building the text (for the file list). */
export function countChanges(before: string, after: string): { linesAdded: number; linesRemoved: number; truncated: boolean } {
  const d = unifiedDiff(before, after, '');
  return { linesAdded: d.linesAdded, linesRemoved: d.linesRemoved, truncated: d.truncated };
}
