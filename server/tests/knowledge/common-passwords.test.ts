import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { KNOWLEDGE_DIR } from './helpers.js';

describe('data/knowledge/common-passwords.txt', () => {
  const text = readFileSync(join(KNOWLEDGE_DIR, 'common-passwords.txt'), 'utf8');
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();

  it('has at least 90,000 entries, one per line, no header', () => {
    expect(lines.length).toBeGreaterThanOrEqual(90_000);
    expect(lines[0]).toBe('123456');
    expect(lines.slice(0, 20)).toContain('password');
  });

  it('every line is lowercase, non-empty and free of surrounding whitespace', () => {
    const bad: string[] = [];
    for (const [i, line] of lines.entries()) {
      if (line.length === 0 || line !== line.trim() || line !== line.toLowerCase()) bad.push(`${i + 1}: ${JSON.stringify(line)}`);
      if (bad.length > 20) break;
    }
    expect(bad).toEqual([]);
  });

  it('contains the classic weak passwords the policy must refuse', () => {
    const set = new Set(lines);
    for (const p of ['123456', 'password', 'qwerty', 'letmein', 'iloveyou', 'admin', 'welcome', 'password1', '123456789', 'abc123']) {
      expect(set.has(p), p).toBe(true);
    }
  });

  it('has very few duplicates (the file is meant to be a set)', () => {
    expect(lines.length - new Set(lines).size).toBeLessThan(100);
  });
});
