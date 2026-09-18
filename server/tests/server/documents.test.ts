/**
 * The documents a human check points at: found where they really are, never a file that holds secrets, and served
 * only from this project.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { documentsFor, readDocument, DocumentNotAvailable } from '../../src/verification/documents.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('documents a check refers to', () => {
  let harness: TestHarness;
  let roots: { appDir: string; projectDir: string; repoRoot: string };
  let projectId: string;

  beforeEach(async () => {
    harness = await buildHarness();
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    projectId = project.id;
    const paths = harness.store.paths(project.id);
    roots = { appDir: paths.appDir, projectDir: paths.dir, repoRoot: harness.config.paths.repoRoot };
    mkdirSync(join(paths.appDir, 'docs'), { recursive: true });
    mkdirSync(join(paths.dir, 'design'), { recursive: true });
    writeFileSync(join(paths.appDir, 'docs', 'sessions.md'), '# How sign-in works\n\nSessions end after 30 minutes.\n');
    writeFileSync(join(paths.appDir, '.env'), 'SESSION_SECRET=super-secret-value\n');
    writeFileSync(join(paths.appDir, 'FIRST-LOGIN.txt'), 'One-time password: hunter2\n');
    writeFileSync(join(paths.dir, 'design', 'threat-model.md'), '# Threat model\n\nWhat could go wrong.\n');
  });
  afterEach(() => harness?.cleanup());

  it('finds the file a check names, wherever it lives, and skips ones that are not there', () => {
    const docs = documentsFor(
      ['Does docs/sessions.md state the idle time?', 'Can you find design/threat-model.md?', 'Read docs/uploads.md as well.'],
      roots,
    );
    expect(docs.map((d) => [d.path, d.where, d.openable])).toEqual([
      ['docs/sessions.md', 'app', true],
      ['design/threat-model.md', 'project', true],
    ]);
  });

  it('names a file that holds secrets but never offers to open it', () => {
    const docs = documentsFor(['Is the .env file only readable by you?', 'Have you deleted FIRST-LOGIN.txt?'], roots);
    expect(docs.map((d) => [d.path, d.openable])).toEqual([
      ['.env', false],
      ['FIRST-LOGIN.txt', false],
    ]);
    expect(() => readDocument('.env', roots)).toThrow(DocumentNotAvailable);
    expect(() => readDocument('FIRST-LOGIN.txt', roots)).toThrow(DocumentNotAvailable);
  });

  it('serves a document over the API and refuses paths outside the project', async () => {
    const { cookie } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie };
    const ok = await request(harness.server).get(`/api/projects/${projectId}/document?path=docs/sessions.md`).set(headers);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ path: 'docs/sessions.md', where: 'app' });
    expect(ok.body.text).toContain('Sessions end after 30 minutes.');

    const secret = await request(harness.server).get(`/api/projects/${projectId}/document?path=.env`).set(headers);
    expect(secret.status).toBe(404);
    expect(secret.body.error.message).toMatch(/may hold secrets/);

    const outside = await request(harness.server).get(`/api/projects/${projectId}/document?path=../../settings.json`).set(headers);
    expect(outside.status).toBeGreaterThanOrEqual(400);
    const missing = await request(harness.server).get(`/api/projects/${projectId}/document?path=docs/nothing.md`).set(headers);
    expect(missing.status).toBe(404);
  });
});
