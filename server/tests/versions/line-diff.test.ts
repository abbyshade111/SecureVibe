/** The line diff behind "what changed": counts and unified hunks. */
import { describe, expect, it } from 'vitest';
import { MAX_LINES, unifiedDiff } from '../../src/versions/line-diff.js';

describe('unifiedDiff', () => {
  it('reports an unchanged file as empty', () => {
    const d = unifiedDiff('a\nb\nc\n', 'a\nb\nc\n', 'x.ts');
    expect(d.linesAdded).toBe(0);
    expect(d.linesRemoved).toBe(0);
    expect(d.text).toBe('--- x.ts (before)\n+++ x.ts (after)\n');
  });

  it('marks added and removed lines with context', () => {
    const before = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'].join('\n');
    const after = ['l1', 'l2', 'l3', 'l4', 'CHANGED', 'l6', 'l7', 'l8', 'l9', 'l10', 'l11'].join('\n');
    const d = unifiedDiff(before, after, 'x.ts');
    expect(d.linesAdded).toBe(2);
    expect(d.linesRemoved).toBe(1);
    expect(d.text).toContain('-l5\n+CHANGED\n');
    expect(d.text).toContain('+l11');
    // Context lines around the change, not the whole file.
    expect(d.text).toContain(' l2\n l3\n l4\n');
    expect(d.text).not.toContain(' l1\n l2');
  });

  it('handles a file that is entirely new or entirely gone', () => {
    expect(unifiedDiff('', 'a\nb\n', 'n.ts').linesAdded).toBe(2);
    expect(unifiedDiff('a\nb\n', '', 'n.ts').linesRemoved).toBe(2);
  });

  it('compares only a prefix of very long files and says so', () => {
    const long = Array.from({ length: MAX_LINES + 50 }, (_, i) => `line ${i}`).join('\n');
    const d = unifiedDiff(long, `${long}\nextra`, 'big.ts');
    expect(d.truncated).toBe(true);
    expect(d.text).toContain('only the first');
  });
});
