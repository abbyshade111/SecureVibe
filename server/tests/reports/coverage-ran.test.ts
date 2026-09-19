/**
 * The "Ran" cell in the tool-coverage tables. A scan that stopped part-way after charging the owner's AI service
 * printed "No" directly above a sentence saying they had been charged: a false cell over a true sentence, which
 * is how a report loses its reader. `ran` stays false so nothing counts coverage the run did not give.
 */
import { describe, expect, it } from 'vitest';
import { coverageRanText } from '../../src/reports/types.js';

describe('what the coverage table says a tool did', () => {
  it('says Yes only for a tool that finished', () => {
    expect(coverageRanText({ ran: true })).toBe('Yes');
  });

  it('says No, with the reason, for a tool that never started', () => {
    expect(coverageRanText({ ran: false, reason: 'skipped: not installed' })).toBe('No (skipped: not installed)');
  });

  it('says Partly for a tool that did some of the work and stopped', () => {
    const reason = 'stopped at the time limit after reading some of your files: your AI service was charged for what it had already read';
    const text = coverageRanText({ ran: false, partial: true, reason });
    expect(text.startsWith('Partly')).toBe(true);
    expect(text).not.toMatch(/^No/);
    expect(text).toContain('charged');
  });

  it('escapes the reason when the report asks it to', () => {
    expect(coverageRanText({ ran: false, reason: '<b>' }, (s) => s.replace('<', '&lt;'))).toBe('No (&lt;b>)');
  });
});
