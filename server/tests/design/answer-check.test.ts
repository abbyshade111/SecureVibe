/** Damaged saved answers are named, with the fix offered; honest answers are left alone. */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkSavedAnswers } from '@shared/answer-check.js';
import type { PartialDesignProfile } from '@shared/profile.js';
import { allProfiles, habitTracker } from '../fixtures/design/profiles.js';
import { REPO_ROOT } from '../knowledge/helpers.js';

function withEntity(entity: Record<string, unknown>): PartialDesignProfile {
  const profile = structuredClone(habitTracker) as PartialDesignProfile;
  profile.app!.entities = [...(profile.app!.entities ?? []), entity as never];
  return profile;
}

describe('checking saved answers', () => {
  it('finds nothing wrong with any honest set of answers', () => {
    // Every fixture profile and every golden app: a check that flags honest answers is worse than none.
    for (const { name, profile } of allProfiles) expect(checkSavedAnswers(profile), name).toEqual([]);
    const goldenDir = join(REPO_ROOT, 'evals', 'golden');
    const golden = readdirSync(goldenDir).filter((f) => f.endsWith('.json'));
    expect(golden.length).toBeGreaterThan(3);
    for (const file of golden) {
      const app = JSON.parse(readFileSync(join(goldenDir, file), 'utf8')) as { profile?: PartialDesignProfile } & PartialDesignProfile;
      expect(checkSavedAnswers(app.profile ?? app), file).toEqual([]);
    }
  });

  it('offers to remove a record type with no details', () => {
    // What the owner's health app had: a record type the follow-up flow added with no fields, so its page was an
    // empty form, and every rebuild made it again.
    const problems = checkSavedAnswers(withEntity({ name: 'treatment', label: 'Treatment', fields: [], access: 'owner-only' }));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ kind: 'record-without-details', label: 'Treatment', offerRemoval: true });
    expect(problems[0]!.entityIndex).toBe((habitTracker.app.entities ?? []).length);
    expect(problems[0]!.message).toMatch(/no details/);
  });

  it('asks about a name that reads like a sentence, and does not decide for the owner', () => {
    const label = 'Run entries and Body Weight Training entries as separate rec';
    const problems = checkSavedAnswers(
      withEntity({ name: 'run-entries-and-body', label, fields: [{ name: 'note', label: 'Note', type: 'text', required: false, sensitive: false }], access: 'owner-only' }),
    );
    expect(problems.map((p) => p.kind)).toEqual(['record-name-looks-like-a-sentence']);
    expect(problems[0]!.offerRemoval).toBe(false);
    // Short, and joined with "and": still a sentence about records, not a record.
    expect(checkSavedAnswers(withEntity({ name: 'x', label: 'Visits and treatments', fields: [{ name: 'a', label: 'A', type: 'text' }], access: 'owner-only' })).map((p) => p.kind)).toEqual([
      'record-name-looks-like-a-sentence',
    ]);
  });

  it('asks about a description that answered a different question', () => {
    const field = { name: 'note', label: 'Note', type: 'text', required: false, sensitive: false };
    const yes = checkSavedAnswers(withEntity({ name: 'visit', label: 'Visit', description: 'Yes, only about me.', fields: [field], access: 'owner-only' }));
    expect(yes.map((p) => p.kind)).toEqual(['record-description-answers-another-question']);
    const copied = checkSavedAnswers(withEntity({ name: 'visit', label: 'Visit', description: habitTracker.app.description, fields: [field], access: 'owner-only' }));
    expect(copied.map((p) => p.kind)).toEqual(['record-description-answers-another-question']);
    const fine = checkSavedAnswers(withEntity({ name: 'visit', label: 'Visit', description: 'One entry per appointment.', fields: [field], access: 'owner-only' }));
    expect(fine).toEqual([]);
  });

  it('leaves a record that is still being typed to the editor', () => {
    expect(checkSavedAnswers(withEntity({ name: '', label: '', fields: [], access: 'owner-only' }))).toEqual([]);
  });

  it('reports every problem on a record, each pointing at the same record', () => {
    const problems = checkSavedAnswers(withEntity({ name: 'x', label: 'Everything I find out about it and what helped', fields: [], access: 'owner-only' }));
    expect(problems.map((p) => p.kind).sort()).toEqual(['record-name-looks-like-a-sentence', 'record-without-details']);
    expect(new Set(problems.map((p) => p.entityIndex)).size).toBe(1);
  });
});
