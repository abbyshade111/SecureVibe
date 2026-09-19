/**
 * Withholding credit from a test named after a rule it does not check — the V2.3.3 case, end to end through the
 * stage that mints test evidence.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Evidence } from '@shared/compliance.js';
import { screenTestEvidence } from '../../src/pipeline/stages/unit-tests.js';
import type { PipelineCtx } from '../../src/pipeline/types.js';

const REQUIREMENTS: Record<string, string> = {
  'V6.3.1': 'Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented.',
  'V2.3.3':
    'Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state.',
  'V6.2.1': 'Verify that user set passwords are at least 8 characters in length.',
};

const PLAIN: Record<string, string> = {
  'V2.3.3': 'A change either happens completely or not at all: if part of it fails, everything goes back as it was.',
  'V6.2.1': 'Passwords must be at least 12 characters long.',
};

function ctxWith(logged: string[] = [], appDir = ''): PipelineCtx {
  return {
    appDir,
    frameworks: { getRequirement: (id: string) => (REQUIREMENTS[id] ? { id, description: REQUIREMENTS[id] } : undefined) },
    knowledge: { requirementsPlain: Object.fromEntries(Object.entries(PLAIN).map(([id, plain]) => [id, { plain }])) },
    log: (_stage: string, message: string) => logged.push(message),
  } as unknown as PipelineCtx;
}

function testEvidence(name: string): Evidence {
  return { id: 'E-1', type: 'test', tier: 'strong', ref: `test:${name}`, summary: `The app's own test "${name}" passed.`, passed: true };
}

describe('a test that may not check what its name claims', () => {
  it('reads the test itself, so a test is judged on what it does and not only on what it is called', () => {
    // "login is limited per account" shares no word with "credential stuffing and password brute force",
    // but the lines of the test say "password" plainly.
    const dir = mkdtempSync(join(tmpdir(), 'sv-screen-'));
    mkdirSync(join(dir, 'tests', 'security'), { recursive: true });
    writeFileSync(
      join(dir, 'tests', 'security', 'rate-limit.test.ts'),
      ["describe('rate-limit', () => {", "  test('V6.3.1 login is limited per account after 5 failures', async () => {", "    const res = await app.login({ password: 'wrong-password' });", '  });', '});'].join('\n'),
    );
    const evidence = [testEvidence('rate-limit > V6.3.1 login is limited per account after 5 failures')];
    const { kept, findings } = screenTestEvidence(ctxWith([], dir), evidence);
    expect(kept).toHaveLength(1);
    expect(findings).toEqual([]);
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports the page-size test that was standing in for transactions, without costing the app its credit', () => {
    const logged: string[] = [];
    const evidence = [testEvidence('V2.3.3 bookings: the list never returns an unbounded result set')];
    const { kept, findings } = screenTestEvidence(ctxWith(logged), evidence);

    // The evidence stands: a word comparison is not grounds for quietly taking coverage away.
    expect(kept).toEqual(evidence);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('tests.name-does-not-match-requirement');
    expect(findings[0]!.impact).toMatch(/still counted as verified/);
    // Mapped to no requirement on purpose: a finding against V2.3.3 would fail a rule the app may well meet.
    expect(findings[0]!.mappings.asvs).toEqual([]);
    expect(findings[0]!.description).toContain('V2.3.3');
    expect(logged[0]).toMatch(/says nothing that V2\.3\.3 says/);
  });

  it('keeps a test that really is about its rule, in either wording', () => {
    const standard = [testEvidence('V2.3.3 a failed booking is rolled back to the previous state')];
    expect(screenTestEvidence(ctxWith(), standard).kept).toHaveLength(1);

    const plainWords = [testEvidence('V2.3.3 when part of a change fails, everything goes back as it was')];
    expect(screenTestEvidence(ctxWith(), plainWords).kept).toHaveLength(1);

    const password = [testEvidence('V6.2.1 a password of 11 characters is refused')];
    expect(screenTestEvidence(ctxWith(), password).kept).toHaveLength(1);
  });

  it('leaves alone anything that is not a test named after a rule', () => {
    const notATest: Evidence = { id: 'E-2', type: 'config', tier: 'medium', ref: 'config.no-debug-flags', summary: 'checked', passed: true };
    const unnamed = testEvidence('the home page loads');
    const { kept, findings } = screenTestEvidence(ctxWith(), [notATest, unnamed]);
    expect(kept).toHaveLength(2);
    expect(findings).toEqual([]);
  });

  it('reports one finding per test, however many requirements it was credited for', () => {
    const twice = [testEvidence('V2.3.3 bookings: the list is capped'), testEvidence('V2.3.3 bookings: the list is capped')];
    const { findings } = screenTestEvidence(ctxWith(), twice);
    expect(findings).toHaveLength(1);
  });

  it('judges nothing when the requirement is one SecureVibe has no wording for', () => {
    const unknown = [testEvidence('V99.9.9 something nobody described')];
    expect(screenTestEvidence(ctxWith(), unknown).kept).toHaveLength(1);
  });
});
