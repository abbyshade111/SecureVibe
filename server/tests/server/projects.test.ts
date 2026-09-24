import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('project CRUD, profile save and validation', () => {
  let harness: TestHarness;
  let cookie: string;
  let csrfToken: string;

  beforeEach(async () => {
    harness = await buildHarness();
    ({ cookie, csrfToken } = await signIn(harness));
  });
  afterEach(() => harness?.cleanup());

  function authed() {
    return { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
  }

  it('rejects a malformed create-project request with a validation error', async () => {
    const res = await request(harness.server).post('/api/projects').set(authed()).send({ name: '' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('validation_error');
    expect(Array.isArray(res.body.error.details)).toBe(true);
  });

  it('creates, lists, reads and deletes a project', async () => {
    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'My Shop', mode: 'guided' });
    expect(create.status).toBe(201);
    const projectId = create.body.project.id as string;
    expect(projectId).toMatch(/^p_[a-z2-7]{10}$/);

    const list = await request(harness.server).get('/api/projects').set(authed());
    expect(list.status).toBe(200);
    expect(list.body.projects.some((p: { id: string }) => p.id === projectId)).toBe(true);

    const read = await request(harness.server).get(`/api/projects/${projectId}`).set(authed());
    expect(read.status).toBe(200);
    expect(read.body.project.name).toBe('My Shop');

    const del = await request(harness.server).delete(`/api/projects/${projectId}`).set(authed());
    expect(del.status).toBe(204);

    const readAfter = await request(harness.server).get(`/api/projects/${projectId}`).set(authed());
    expect(readAfter.status).toBe(404);
  });

  it('archives and restores an app without deleting it, and deletes it on request', async () => {
    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'Old idea', mode: 'guided' });
    const projectId = create.body.project.id as string;

    const archived = await request(harness.server).post(`/api/projects/${projectId}/archive`).set(authed());
    expect(archived.status).toBe(200);
    let list = await request(harness.server).get('/api/projects').set(authed());
    expect(list.body.projects.find((p: { id: string }) => p.id === projectId).archivedAt).toBeTruthy();

    const restored = await request(harness.server).post(`/api/projects/${projectId}/restore`).set(authed());
    expect(restored.status).toBe(200);
    list = await request(harness.server).get('/api/projects').set(authed());
    expect(list.body.projects.find((p: { id: string }) => p.id === projectId).archivedAt).toBeUndefined();

    const removed = await request(harness.server).delete(`/api/projects/${projectId}`).set(authed());
    expect(removed.status).toBe(204);
    expect((await request(harness.server).get(`/api/projects/${projectId}`).set(authed())).status).toBe(404);
    expect((await request(harness.server).post(`/api/projects/${projectId}/archive`).set(authed())).status).toBe(404);
  });

  it('404s for an id that looks well-formed but does not exist', async () => {
    const res = await request(harness.server).get('/api/projects/p_zzzzzzzzzz').set(authed());
    expect(res.status).toBe(404);
  });

  it('saves a partial profile, merging by section, and marks the design stale once a full profile changes', async () => {
    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'Stock Tracker', mode: 'guided' });
    const projectId = create.body.project.id as string;

    const step1 = await request(harness.server)
      .put(`/api/projects/${projectId}/profile`)
      .set(authed())
      .send({ profile: { app: { name: 'Stock Tracker', description: 'Tracks shop inventory across two locations.', category: 'inventory' } }, wizardStep: 1 });
    expect(step1.status).toBe(200);
    expect(step1.body.project.profile.app.name).toBe('Stock Tracker');
    expect(step1.body.project.wizardStep).toBe(1);

    const step2 = await request(harness.server)
      .put(`/api/projects/${projectId}/profile`)
      .set(authed())
      .send({ profile: { users: { audience: 'my-team', requiresSignIn: true }, data: { categories: ['business-confidential'] }, deployment: { target: 'local-only', owner: { name: 'Sam', contactEmail: 'sam@example.com' } } } });
    expect(step2.status).toBe(200);
    // The app section from step 1 must still be present after step 2 only touched other sections.
    expect(step2.body.project.profile.app.name).toBe('Stock Tracker');
    expect(step2.body.project.profile.users.audience).toBe('my-team');

    const design = await request(harness.server).post(`/api/projects/${projectId}/design`).set(authed());
    expect(design.status).toBe(200);
    expect(design.body.design.applicability).toBeDefined();

    const changed = await request(harness.server)
      .put(`/api/projects/${projectId}/profile`)
      .set(authed())
      .send({ profile: { deployment: { businessImpact: 'high' } } });
    expect(changed.status).toBe(200);
    expect(changed.body.project.designStale).toBe(true);

    // Renaming the app in the answers renames it in "My apps" as well.
    const renamed = await request(harness.server)
      .put(`/api/projects/${projectId}/profile`)
      .set(authed())
      .send({ profile: { app: { name: 'Shop Stock' } } });
    expect(renamed.status).toBe(200);
    expect(renamed.body.project.name).toBe('Shop Stock');
    const list = await request(harness.server).get('/api/projects').set(authed());
    expect((list.body.projects as { id: string; name: string }[]).find((p) => p.id === projectId)?.name).toBe('Shop Stock');
  });

  it('saves a record that is still being typed, and refuses to design from it', async () => {
    // Every keystroke autosaves. The moment an owner cleared "New record" to type their own name, the save was
    // refused for an empty label and the page said "Not saved yet" about the thing they were in the middle of.
    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'Drafts', mode: 'guided' });
    const projectId = create.body.project.id as string;
    const draft = await request(harness.server)
      .put(`/api/projects/${projectId}/profile`)
      .set(authed())
      .send({ profile: { app: { entities: [{ name: '', label: '', fields: [{ name: '', label: '', type: 'text' }], access: 'owner-only' }] } } });
    expect(draft.status).toBe(200);
    expect(draft.body.project.profile.app.entities[0].label).toBe('');
    // The strict rules still hold where they matter: a design cannot be made from a nameless record.
    const design = await request(harness.server).post(`/api/projects/${projectId}/design`).set(authed());
    expect(design.status).toBe(400);
  });

  it('rejects design derivation when the profile is incomplete', async () => {
    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'Incomplete', mode: 'guided' });
    const projectId = create.body.project.id as string;
    const res = await request(harness.server).post(`/api/projects/${projectId}/design`).set(authed());
    expect(res.status).toBe(400);
  });

  it('lists the example projects and can start a project from one', async () => {
    const examples = await request(harness.server).get('/api/examples').set(authed());
    expect(examples.status).toBe(200);
    expect(examples.body.examples.length).toBeGreaterThan(0);
    const exampleId = examples.body.examples[0].id as string;

    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'From example', mode: 'guided', exampleId });
    expect(create.status).toBe(201);
    expect(create.body.project.profile.app).toBeDefined();
  });

  it('copies an app: same answers and design, nothing built, and the original untouched', async () => {
    const examples = await request(harness.server).get('/api/examples').set(authed());
    const exampleId = examples.body.examples[0].id as string;
    const create = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'Original', mode: 'guided', exampleId });
    expect(create.status).toBe(201);
    const sourceId = create.body.project.id as string;
    const designed = await request(harness.server).post(`/api/projects/${sourceId}/design`).set(authed()).send({});
    expect(designed.status).toBe(200);
    const before = harness.store.mustGet(sourceId);
    expect(before.design).toBeDefined();

    const copied = await request(harness.server).post(`/api/projects/${sourceId}/copy`).set(authed()).send({});
    expect(copied.status).toBe(201);
    const copy = copied.body.project as { id: string; name: string; status: string; runs: unknown[]; profile: { app: { name: string; entities: unknown[] } }; design?: unknown; copiedFrom?: { projectId: string } };
    expect(copy.id).not.toBe(sourceId);
    expect(copy.name).toBe('Original (copy)');
    expect(copy.profile.app.name).toBe('Original (copy)');
    expect(copy.profile.app.entities).toEqual(before.profile.app?.entities);
    expect(copy.design).toBeDefined();
    expect(copy.status).toBe('designed');
    expect(copy.runs).toEqual([]);
    expect(copy.copiedFrom?.projectId).toBe(sourceId);
    // Nothing built came with it, and the original is exactly as it was.
    expect(harness.store.listRunIds(copy.id)).toEqual([]);
    expect(harness.store.mustGet(sourceId)).toEqual(before);

    const named = await request(harness.server).post(`/api/projects/${sourceId}/copy`).set(authed()).send({ name: 'Second try' });
    expect(named.status).toBe(201);
    expect(named.body.project.name).toBe('Second try');

    const uploaded = await request(harness.server).post('/api/projects').set(authed()).send({ name: 'Theirs', mode: 'guided', uploaded: { aiAssisted: false } });
    const refused = await request(harness.server).post(`/api/projects/${uploaded.body.project.id}/copy`).set(authed()).send({});
    expect(refused.status).toBe(400);
    expect(refused.body.error.message).toMatch(/no answers to copy/);
  });

  it('reports the framework summary', async () => {
    const res = await request(harness.server).get('/api/frameworks/summary').set(authed());
    expect(res.status).toBe(200);
    expect(res.body.asvs.requirements).toBeGreaterThan(0);
    expect(res.body.sbd.controls).toBeGreaterThan(0);
  });
});
