/** The follow-up questions route: what the owner accepts is applied to their answers, and nothing else is. */
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ScriptedProvider } from '../../src/llm/scripted.js';
import { FIXTURE_DIR } from '../llm/helpers.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('follow-up questions over the API', () => {
  let harness: TestHarness;
  let headers: Record<string, string>;

  beforeEach(async () => {
    harness = await buildHarness({ provider: new ScriptedProvider({ dir: FIXTURE_DIR, scenario: 'refine' }) });
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
  });
  afterEach(() => harness?.cleanup());

  it('asks, then applies only what the owner chose', async () => {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });

    const asked = await request(harness.server).post(`/api/projects/${project.id}/refine`).set(headers).send({});
    expect(asked.status).toBe(200);
    const refinement = asked.body.refinement as { questions: { id: string; field?: string }[]; features: { id: string; field: string }[] };
    expect(refinement.questions.length).toBe(4);
    expect(refinement.features.map((f) => f.field)).toEqual(['app.keyFeatures.add', 'app.entities.add']);
    // It is kept with the app, so the reports can show a person went through it.
    expect(harness.store.mustGet(project.id).refinement?.performedBy).toBe('claude');

    const featuresBefore = harness.store.mustGet(project.id).profile.app?.keyFeatures?.length ?? 0;
    const decided = await request(harness.server)
      .post(`/api/projects/${project.id}/refine/decisions`)
      .set(headers)
      .send({
        answers: [
          { questionId: refinement.questions[0]!.id, value: 'my-team' },
          // An answer the question never offered is recorded but changes nothing.
          { questionId: refinement.questions[2]!.id, value: 'maybe-later' },
        ],
        features: [
          { suggestionId: refinement.features[0]!.id, accepted: true },
          { suggestionId: refinement.features[1]!.id, accepted: false },
        ],
      });
    expect(decided.status).toBe(200);

    const saved = harness.store.mustGet(project.id);
    expect(saved.profile.users?.audience).toBe('my-team');
    expect(saved.profile.data?.aboutOtherPeople).toBe(habitTracker.data.aboutOtherPeople);
    expect(saved.profile.app?.keyFeatures?.length).toBe(featuresBefore + 1);
    // The declined suggestion added no record type.
    expect((saved.profile.app?.entities ?? []).some((e) => e?.name === 'treatment')).toBe(false);
    expect(saved.refinement?.questions[0]?.answer).toBe('my-team');
    expect(saved.refinement?.features[1]?.accepted).toBe(false);
  });

  it('adds every record the owner picked from a question that takes several', async () => {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const asked = await request(harness.server).post(`/api/projects/${project.id}/refine`).set(headers).send({});
    const questions = asked.body.refinement.questions as { id: string; field?: string; multiple: boolean; options: { value: string }[] }[];
    const records = questions.find((q) => q.field === 'app.entities.add')!;
    expect(records.multiple).toBe(true);
    const audience = questions.find((q) => q.field === 'users.audience')!;
    expect(audience.multiple).toBe(false);
    const entitiesBefore = harness.store.mustGet(project.id).profile.app?.entities?.length ?? 0;

    const decided = await request(harness.server)
      .post(`/api/projects/${project.id}/refine/decisions`)
      .set(headers)
      .send({
        answers: [
          // Three of the four: the fourth is a sentence, not a record name, and the apply step refuses it.
          { questionId: records.id, values: ['Symptom', 'Medication', records.options[3]!.value, 'Diary'] },
          // A question that takes one answer, sent two: recorded, and nothing applied rather than guessing.
          { questionId: audience.id, values: ['just-me', 'my-team'] },
        ],
      });
    expect(decided.status).toBe(200);

    const saved = harness.store.mustGet(project.id);
    const names = (saved.profile.app?.entities ?? []).map((e) => e?.name);
    expect(names).toContain('symptom');
    expect(names).toContain('medication');
    // "Diary" was never offered by the question, so it is not added.
    expect(names).not.toContain('diary');
    expect(names.some((n) => (n ?? '').startsWith('everything'))).toBe(false);
    expect(saved.profile.app?.entities?.length).toBe(entitiesBefore + 2);
    expect(saved.refinement?.questions.find((q) => q.id === records.id)?.answers).toEqual(['Symptom', 'Medication', records.options[3]!.value, 'Diary']);
    expect(saved.profile.users?.audience).toBe(habitTracker.users.audience);
    expect(saved.refinement?.questions.find((q) => q.id === audience.id)?.answered).toBe(true);
  });

  it('records that the owner moved on without finishing', async () => {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await request(harness.server).post(`/api/projects/${project.id}/refine`).set(headers).send({});
    const res = await request(harness.server).post(`/api/projects/${project.id}/refine/decisions`).set(headers).send({ dismiss: true });
    expect(res.status).toBe(200);
    expect(harness.store.mustGet(project.id).refinement?.dismissedAt).toBeDefined();
  });

  it('needs AI, and says so plainly', async () => {
    harness.cleanup();
    harness = await buildHarness();
    const { cookie, csrfToken } = await signIn(harness);
    const noAi = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const res = await request(harness.server).post(`/api/projects/${project.id}/refine`).set(noAi).send({});
    expect(res.status).toBe(503);
    expect(res.body.error.message).toMatch(/Follow-up questions need AI/);
  });
});
