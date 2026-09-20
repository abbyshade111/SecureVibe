/**
 * What the generation agent is told when a check fails.
 *
 * It used to be a count — "1 of 223 failing" — while the same result object carried every test's name, file and
 * assertion message. On the first app built by someone new, the agent reported that it could not isolate the
 * failure because the tool returns a summary rather than names; it re-ran the suite twice, spent the owner's
 * budget, and recommended she run it again herself. The information existed and we withheld it.
 */
import { describe, expect, it } from 'vitest';
import { formatTestCheckOutput } from '../../src/pipeline/checks.js';

describe('what a failed test run tells the agent', () => {
  const details = {
    total: 223,
    failed: 2,
    tests: [
      { name: 'antibodies > search returns only your own rows', ok: true },
      { name: 'antibodies > compare rejects a missing id', ok: false, file: 'tests/features/compare.test.ts', detail: 'expected 400 to be 404' },
      { name: 'uploads > refuses an oversized file', ok: false, file: 'tests/security/uploads.test.ts' },
      { name: 'ai > assistant is available', ok: true, skipped: true },
    ],
  };

  it('names every failing test, with its file and what went wrong', () => {
    const out = formatTestCheckOutput('Ran 223 tests', details);
    expect(out).toContain('antibodies > compare rejects a missing id');
    expect(out).toContain('tests/features/compare.test.ts');
    expect(out).toContain('expected 400 to be 404');
    expect(out).toContain('uploads > refuses an oversized file');
  });

  it('does not report a skipped test as a failure', () => {
    // A skipped test is a feature the app does not have, not something broken. Telling the agent otherwise sends
    // it hunting for a fault that does not exist, at the owner's expense.
    expect(formatTestCheckOutput('Ran 223 tests', details)).not.toContain('assistant is available');
  });

  it('says nothing about failures when nothing failed', () => {
    const clean = { total: 10, failed: 0, tests: [{ name: 'a passing test', ok: true }] };
    expect(formatTestCheckOutput('Ran 10 tests', clean)).not.toMatch(/Failing:/);
  });
});
