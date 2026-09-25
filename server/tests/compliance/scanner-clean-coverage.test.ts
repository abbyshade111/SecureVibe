/**
 * A requirement may only be classed "scanner-clean" (verified by the absence of findings) when a static rule
 * actually looks for it. The class was applied to V1.2.3 and V11.2.1 with no rule behind either, and the engine
 * credited a clean scan for them regardless.
 */
import { describe, expect, it } from 'vitest';
import { staticRulesCovering } from '../../src/compliance/evidence.js';
import { loadFrameworks, loadKnowledge, verificationClassFor } from '../../src/frameworks/index.js';

describe('scanner-clean requirements', () => {
  const knowledge = loadKnowledge({ warn: () => {} });
  const frameworks = loadFrameworks();
  const asvs = frameworks.listRequirements('asvs');

  it('the real rule set covers every ASVS requirement classed scanner-clean', () => {
    const classed = asvs.filter((r) => verificationClassFor(r.id, knowledge) === 'scanner-clean');
    expect(classed.length).toBeGreaterThan(5);
    const uncovered = classed.filter((r) => staticRulesCovering('asvs', r.id).length === 0).map((r) => r.id);
    expect(uncovered, `classed scanner-clean but no static rule covers them: ${uncovered.join(', ')}`).toEqual([]);
  });

  it('the two requirements that were classed that way with no rule now rest on AI review or a person, and say so', () => {
    for (const id of ['V1.2.3', 'V11.2.1']) {
      expect(staticRulesCovering('asvs', id), id).toEqual([]);
      expect(verificationClassFor(id, knowledge), id).toBe('ai-assistable');
    }
  });
});
