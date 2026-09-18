import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { RequirementPlainSchema } from '@shared/knowledge.js';
import { levelOneAndTwoIds, loadFrameworkIds, plainLanguageProblems, readKnowledge } from './helpers.js';

const raw = readKnowledge<unknown>('requirements-plain.json');

describe('data/knowledge/requirements-plain.json', () => {
  const entries = z.array(RequirementPlainSchema).parse(raw);
  const byId = new Map(entries.map((e) => [e.id, e]));

  it('validates against RequirementPlainSchema and has no duplicate ids', () => {
    expect(entries.length).toBeGreaterThan(400);
    expect(byId.size).toBe(entries.length);
  });

  it('only references requirement ids that exist in the framework files', () => {
    const { requirements } = loadFrameworkIds();
    const unknown = entries.filter((e) => !requirements.has(e.id)).map((e) => e.id);
    expect(unknown).toEqual([]);
  });

  it('covers every ASVS, AISVS and Appendix C requirement at levels 1 and 2', () => {
    const missing = levelOneAndTwoIds().filter((id) => !byId.has(id));
    expect(missing).toEqual([]);
  });

  it('covers each standard, not just one', () => {
    const { requirements } = loadFrameworkIds();
    const counts = { asvs: 0, aisvs: 0, 'aisvs-appendix-c': 0 };
    for (const e of entries) counts[requirements.get(e.id)!.standard]++;
    expect(counts.asvs).toBeGreaterThan(200);
    expect(counts.aisvs).toBeGreaterThan(100);
    expect(counts['aisvs-appendix-c']).toBeGreaterThan(20);
  });

  it('every entry has a plain explanation of one to three sentences that is not a copy of the requirement', () => {
    const { requirements } = loadFrameworkIds();
    for (const e of entries) {
      expect(e.plain.trim().length, e.id).toBeGreaterThan(20);
      const sentences = e.plain.split(/(?<=[.!?])\s+/).filter(Boolean);
      expect(sentences.length, `${e.id} sentence count`).toBeLessThanOrEqual(4);
      expect(e.plain.startsWith('Verify that'), `${e.id} must not start like the standard's own wording`).toBe(false);
      expect(e.plain, `${e.id} must not copy the requirement text`).not.toBe(requirements.get(e.id)!.description);
      const problems = plainLanguageProblems(e.plain, { checkAcronyms: false });
      expect(problems, e.id).toEqual([]);
    }
  });

  it('every entry has manual verification guidance shaped for the person who can do it', () => {
    for (const e of entries) {
      expect(e.manual, `${e.id} has no manual block`).toBeDefined();
      const m = e.manual!;
      if (m.whoCanDo === 'owner') {
        expect(m.question, `${e.id}: owner-checkable items need a yes/no question`).toBeTruthy();
        expect(m.question!.trim().endsWith('?'), `${e.id}: owner question should end with ?`).toBe(true);
      } else {
        expect(m.steps.length, `${e.id}: ${m.whoCanDo} items need steps`).toBeGreaterThan(0);
      }
      expect(m.whatCountsAsEvidence, `${e.id}: what counts as evidence`).toBeTruthy();
    }
  });

  it('manual guidance is specific: applicable requirements do not share the same steps and question', () => {
    // Chapters that never apply to a v1 app (OAuth server, WebRTC, MCP, model training, CI/CD…) legitimately share
    // one "confirm the feature is absent" check; those entries mark their evidence as "Not applicable.".
    const seen = new Map<string, string>();
    const collisions: string[] = [];
    for (const e of entries) {
      if (e.manual!.whatCountsAsEvidence === 'Not applicable.') continue;
      const key = JSON.stringify([e.manual!.question ?? '', e.manual!.steps]);
      const prev = seen.get(key);
      if (prev) collisions.push(`${prev} ~ ${e.id}`);
      else seen.set(key, e.id);
    }
    // A handful of near-identical requirements legitimately share a check; anything more means generic filler.
    expect(collisions.length, collisions.join('\n')).toBeLessThanOrEqual(10);
  });

  it('never-applicable entries still explain, per requirement, what the requirement is about', () => {
    const na = entries.filter((e) => e.manual!.whatCountsAsEvidence === 'Not applicable.');
    expect(na.length).toBeGreaterThan(0);
    expect(na.length, 'most requirements must have a real check').toBeLessThan(entries.length / 3);
    const plains = new Set(na.map((e) => e.plain));
    expect(plains.size, 'plain text must be specific even when the check is shared').toBe(na.length);
  });

  it('uses a mix of owner, developer, security-professional and hosting-provider checks', () => {
    const who = new Set(entries.map((e) => e.manual!.whoCanDo));
    expect([...who].sort()).toEqual(['developer', 'hosting-provider', 'owner', 'security-professional']);
    const ownerCount = entries.filter((e) => e.manual!.whoCanDo === 'owner').length;
    expect(ownerCount).toBeGreaterThan(40);
  });
});
