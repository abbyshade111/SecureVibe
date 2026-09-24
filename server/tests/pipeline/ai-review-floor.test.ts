/** Without the answers, the AI review reads the code against ASVS Level 1: the floor, and only the floor. */
import { describe, expect, it } from 'vitest';
import { loadFrameworks } from '../../src/frameworks/index.js';
import { requirementIdsWithoutAnswers } from '../../src/pipeline/stages/ai-review.js';

describe('the review without answers', () => {
  it('is every ASVS Level 1 requirement and nothing above it or from another standard', () => {
    const frameworks = loadFrameworks();
    const ids = requirementIdsWithoutAnswers(frameworks);
    expect(ids.length).toBeGreaterThan(50);
    for (const id of ids) {
      const r = frameworks.getRequirement(id)!;
      expect(r.level, id).toBe(1);
      expect(id.startsWith('V'), id).toBe(true);
    }
    const level2 = frameworks.listRequirements('asvs').filter((r) => r.level === 2).map((r) => r.id);
    expect(level2.length).toBeGreaterThan(0);
    for (const id of level2) expect(ids).not.toContain(id);
  });
});
