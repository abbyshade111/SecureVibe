/**
 * Follow-up questions and suggested features: what Claude may set is fenced to an allow-list, and accepting a
 * suggestion only ever adds to the owner's answers.
 */
import { describe, expect, it } from 'vitest';
import { answerFieldAllowed, refineProfile } from '../../src/llm/flows/refine.js';
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
    expect(refinement.questions).toHaveLength(3);

    const [audience, backups, aboutOthers] = refinement.questions;
    expect(audience!.field).toBe('users.audience');
    expect(audience!.options.map((o) => o.value)).toEqual(['just-me', 'my-team']);
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
    expect(added).toMatchObject({ label: 'Treatment note', access: 'all-signed-in' });
    // Adding the same thing twice changes nothing.
    expect(applyRefinement(withEntity, 'app.entities.add', 'Treatment note').app?.entities?.length).toBe(withEntity.app?.entities?.length);
    expect(applyRefinement(withFeature, 'app.keyFeatures.add', 'keep a note for each visit').app?.keyFeatures?.length).toBe(withFeature.app?.keyFeatures?.length);
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
