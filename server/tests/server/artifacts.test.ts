import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PipelineRunSchema } from '@shared/pipeline.js';
import { newRunId } from '../../src/store/index.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('report downloads', () => {
  let harness: TestHarness;
  beforeEach(async () => {
    harness = await buildHarness();
  });
  afterEach(() => harness?.cleanup());

  it('serves reports listed with project-relative paths and with the older file-name-only paths', async () => {
    const project = harness.store.create({ name: 'Report test', mode: 'guided' });
    const runId = newRunId();
    const dir = harness.store.reportsDir(project.id, runId);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'overview.html'), '<style>body{color:red}</style><p>overview</p>');
    writeFileSync(join(dir, 'security-report.html'), '<style>a{color:blue}</style><header class="report-header"></header><p>security</p>');
    const run = PipelineRunSchema.parse({
      id: runId,
      projectId: project.id,
      mode: 'full',
      startedAt: new Date().toISOString(),
      status: 'succeeded',
      stages: [],
      artifacts: [
        { name: 'overview.html', path: `reports/${runId}/overview.html`, kind: 'overview', format: 'html', sizeBytes: 15, description: 'x' },
        { name: 'security-report.html', path: 'security-report.html', kind: 'security-report', format: 'html', sizeBytes: 15, description: 'x' },
      ],
    });
    await harness.store.writeRun(run);
    harness.store.update(project.id, (p) => {
      p.lastRunId = runId;
    });

    const { cookie } = await signIn(harness);
    for (const [name, body] of [['overview.html', 'overview'], ['security-report.html', 'security']] as const) {
      const res = await request(harness.server).get(`/api/projects/${project.id}/artifacts/${name}`).set('Host', '127.0.0.1').set('Cookie', cookie);
      expect(res.status, name).toBe(200);
      expect(res.text).toContain(body);
    }
    const page = await request(harness.server).get(`/api/projects/${project.id}/artifacts/overview.html`).set('Host', '127.0.0.1').set('Cookie', cookie);
    const hash = createHash('sha256').update('body{color:red}').digest('base64');
    expect(page.headers['content-security-policy']).toContain(`style-src 'sha256-${hash}'`);
    expect(page.headers['content-security-policy']).toContain("default-src 'none'");
    // Only SecureVibe's own page may frame a report (to print it); other sites may not.
    expect(page.headers['content-security-policy']).toContain("frame-ancestors 'self'");
    expect(page.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(page.headers['content-security-policy']).not.toContain('unsafe-inline');

    // A report saved by an older version is shown with the current stylesheet (readable in dark mode).
    const older = await request(harness.server).get(`/api/projects/${project.id}/artifacts/security-report.html`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(older.text).toContain('prefers-color-scheme: dark');
    expect(older.text).not.toContain('a{color:blue}');

    // The run is listed in the report history and its reports are reachable by run, also after a newer run.
    const history = await request(harness.server).get(`/api/projects/${project.id}/report-runs`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(history.body.runs.map((r: { id: string }) => r.id)).toEqual([runId]);
    harness.store.update(project.id, (p) => {
      p.lastRunId = undefined;
    });
    const byPath = await request(harness.server).get(`/api/projects/${project.id}/reports/${runId}/overview.html`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(byPath.status).toBe(200);
    const byQuery = await request(harness.server).get(`/api/projects/${project.id}/artifacts?run=${runId}`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(byQuery.body.artifacts).toHaveLength(2);
    const otherProject = harness.store.create({ name: 'Other', mode: 'guided' });
    const foreign = await request(harness.server).get(`/api/projects/${otherProject.id}/reports/${runId}/overview.html`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(foreign.status).toBe(404);
    const bogus = await request(harness.server).get(`/api/projects/${project.id}/reports/..%2F..%2Fsecret/overview.html`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(bogus.status).toBe(404);
  });
});
