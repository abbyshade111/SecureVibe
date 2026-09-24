/**
 * Follow-up questions and suggested features: what Claude may set is fenced to an allow-list, and accepting a
 * suggestion only ever adds to the owner's answers.
 */
import { describe, expect, it } from 'vitest';
import { answerFieldAllowed, answerFieldTakesMany, refineProfile } from '../../src/llm/flows/refine.js';
import { applyRefinement, entityName } from '../../src/design/refine-apply.js';
import { NullProvider } from '../../src/llm/null.js';
import { ScriptedProvider } from '../../src/llm/scripted.js';
import { FIXTURE_DIR } from './helpers.js';
import { habitTracker } from '../fixtures/design/profiles.js';

const provider = () => new ScriptedProvider({ dir: FIXTURE_DIR, scenario: 'refine' });

describe('follow-up questions', () => {
  it('keeps the questions it can act on and drops answers that are not allowed', async () => {
    const { refinement } = await refineProfile(provider(), { app: { description: 'A place to keep what I find out about a health problem.' } }, { projectId: 'p1' });
    expect(refinement.performedBy).toBe('claude');
    expect(refinement.questions).toHaveLength(4);

    const [audience, backups, aboutOthers, records] = refinement.questions;
    expect(audience!.field).toBe('users.audience');
    expect(audience!.options.map((o) => o.value)).toEqual(['just-me', 'my-team']);
    // Two options, but the answer it sets holds one value: the owner picks one.
    expect(audience!.multiple).toBe(false);
    // Record types are a list, so this question takes several answers.
    expect(records!.field).toBe('app.entities.add');
    expect(records!.multiple).toBe(true);
    expect(records!.options).toHaveLength(4);
    // A question with nothing to set is still asked; the answer is recorded as a note.
    expect(backups!.field).toBeUndefined();
    // "maybe-later" is not a value this answer accepts, so that option is gone — and with no usable option left,
    // the question no longer claims to set anything.
    expect(aboutOthers!.options.map((o) => o.value)).toEqual(['true']);
    expect(aboutOthers!.field).toBe('data.aboutOtherPeople');
    expect(refinement.questions.every((q) => q.answered === false)).toBe(true);
  });

  it('keeps only the suggested features it is allowed to apply', async () => {
    const { refinement } = await refineProfile(provider(), { app: { description: 'Research notes.' } }, { projectId: 'p1' });
    expect(refinement.features.map((f) => f.field)).toEqual(['app.keyFeatures.add', 'app.entities.add']);
    expect(refinement.features.every((f) => f.accepted === null)).toBe(true);
    // Neither an unknown field nor one that would weaken the design survives.
    expect(JSON.stringify(refinement.features)).not.toContain('analytics');
    expect(JSON.stringify(refinement.features)).not.toContain('registration');
  });

  it('is skipped honestly without AI', async () => {
    const { refinement } = await refineProfile(new NullProvider('none'), { app: { description: 'x' } });
    expect(refinement.performedBy).toBe('skipped');
    expect(refinement.questions).toEqual([]);
    expect(refinement.skippedReason).toMatch(/not configured/);
  });

  it('only allows fields and values from the list', () => {
    expect(answerFieldAllowed('users.audience', 'just-me')).toBe(true);
    expect(answerFieldAllowed('users.audience', 'everyone')).toBe(false);
    expect(answerFieldAllowed('users.registration', 'open')).toBe(false);
    expect(answerFieldAllowed('app.keyFeatures.add', 'Keep a note')).toBe(true);
    expect(answerFieldAllowed('app.keyFeatures.add', '')).toBe(false);
  });

  it('lets only the two list fields take several answers', () => {
    // Every field on the allow-list is either a list to append to or one setting; only the lists take several.
    expect(answerFieldTakesMany('app.keyFeatures.add')).toBe(true);
    expect(answerFieldTakesMany('app.entities.add')).toBe(true);
    expect(answerFieldTakesMany('users.audience')).toBe(false);
    expect(answerFieldTakesMany('data.retention')).toBe(false);
    expect(answerFieldTakesMany('capabilities.email')).toBe(false);
    expect(answerFieldTakesMany('app.description')).toBe(false);
  });
});

describe('applying an accepted answer', () => {
  it('appends a feature and a record without touching what the owner wrote', () => {
    const before = structuredClone(habitTracker) as Record<string, unknown>;
    const withFeature = applyRefinement(habitTracker, 'app.keyFeatures.add', 'Keep a note for each visit');
    expect(withFeature.app?.keyFeatures).toContain('Keep a note for each visit');
    expect(withFeature.app?.keyFeatures?.length).toBe((habitTracker.app.keyFeatures?.length ?? 0) + 1);
    // The original answers object is untouched (the caller decides what to save).
    expect(habitTracker as unknown as Record<string, unknown>).toEqual(before);

    const withEntity = applyRefinement(withFeature, 'app.entities.add', 'Treatment note');
    const added = withEntity.app?.entities?.find((e) => e?.name === 'treatment-note');
    // Owner-only, not all-signed-in: this flow may only move an answer to the safer side, and the owner never saw
    // this record type to decide who should reach it. An app built for one person had a record type added this
    // way that every signed-in person could read and write.
    expect(added).toMatchObject({ label: 'Treatment note', access: 'owner-only' });
    // Adding the same thing twice changes nothing.
    expect(applyRefinement(withEntity, 'app.entities.add', 'Treatment note').app?.entities?.length).toBe(withEntity.app?.entities?.length);
    expect(applyRefinement(withFeature, 'app.keyFeatures.add', 'keep a note for each visit').app?.keyFeatures?.length).toBe(withFeature.app?.keyFeatures?.length);
  });

  it('refuses a sentence about records as the name of a record', () => {
    // What an owner actually met: answering "Run entries and Body Weight Training entries as separate records"
    // added a third record type with that sentence as its name, cut off mid-word, and no fields — so its page
    // offered a form with nothing to fill in, beside the two record types the sentence was describing.
    const before = applyRefinement(habitTracker as never, 'app.entities.add', 'Habit');
    const after = applyRefinement(before, 'app.entities.add', 'Run entries and Body Weight Training entries as separate records');
    expect(after.app?.entities?.length).toBe(before.app?.entities?.length);
    expect(after.app?.entities?.some((e) => (e?.label ?? '').includes('separate rec'))).toBe(false);
    // A plain name still works.
    expect(applyRefinement(before, 'app.entities.add', 'Workout')?.app?.entities?.some((e) => e?.name === 'workout')).toBe(true);
  });

  it('sets the allowed answers and ignores anything else', () => {
    expect(applyRefinement({}, 'users.audience', 'my-team').users?.audience).toBe('my-team');
    expect(applyRefinement({}, 'data.aboutOtherPeople', 'true').data?.aboutOtherPeople).toBe(true);
    expect(applyRefinement({}, 'capabilities.aiAssistant.canSearchWeb', 'true').capabilities?.aiAssistant?.canSearchWeb).toBe(true);
    expect(applyRefinement({}, 'users.registration', 'open')).toEqual({ app: {}, users: {}, data: {}, capabilities: {} });
  });

  it('turns a label into a record name', () => {
    expect(entityName('Treatment note')).toBe('treatment-note');
    expect(entityName('  Visit / follow-up  ')).toBe('visit-follow-up');
    expect(entityName('!!!')).toBe('record');
  });
});
