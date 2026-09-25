import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PipelineRunSchema } from '@shared/pipeline.js';
import { unpackZip } from '../../src/api/zip.js';
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
    // Nothing frames a report: the PDF is a file SecureVibe writes, not a print dialog opened in a hidden frame.
    expect(page.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(page.headers['x-frame-options']).toBe('DENY');
    expect(page.headers['content-security-policy']).not.toContain('unsafe-inline');

    // A report saved by an older version is shown with the current stylesheet (readable in dark mode).
    const older = await request(harness.server).get(`/api/projects/${project.id}/artifacts/security-report.html`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(older.text).toContain('prefers-color-scheme: dark');
    expect(older.text).not.toContain('a{color:blue}');

    // A run saved before PDFs were written with the reports has none: the PDF is made from its HTML on request.
    const binary = (res: import('superagent').Response, done: (err: Error | null, body: Buffer) => void) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => done(null, Buffer.concat(chunks)));
    };
    const made = await request(harness.server).get(`/api/projects/${project.id}/artifacts/overview.pdf`).set('Host', '127.0.0.1').set('Cookie', cookie).buffer(true).parse(binary);
    expect(made.status).toBe(200);
    expect(made.headers['content-type']).toBe('application/pdf');
    expect(made.headers['content-disposition']).toBe('attachment; filename="overview.pdf"');
    expect((made.body as Buffer).subarray(0, 5).toString('latin1')).toBe('%PDF-');
    const nothing = await request(harness.server).get(`/api/projects/${project.id}/artifacts/no-such-report.pdf`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(nothing.status).toBe(404);

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
  it('offers the scan data for a run as a zip, named after the app and the build', async () => {
    const project = harness.store.create({ name: 'Scan data test', mode: 'guided' });
    const runId = newRunId();
    const dir = harness.store.reportsDir(project.id, runId);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'findings.sarif'), '{"runs":[]}');
    const run = PipelineRunSchema.parse({
      id: runId,
      projectId: project.id,
      mode: 'full',
      startedAt: new Date().toISOString(),
      status: 'succeeded',
      stages: [{ id: 'sast', status: 'passed', summary: 'Nothing found.', details: { rules: 41 }, round: 0 }],
      coverage: [{ tool: 'semgrep', ran: false, reason: 'not installed' }],
      findings: [],
      artifacts: [{ name: 'findings.sarif', path: `reports/${runId}/findings.sarif`, kind: 'sarif', format: 'sarif', sizeBytes: 11, description: 'x' }],
    });
    await harness.store.writeRun(run);
    harness.store.update(project.id, (p) => {
      p.lastRunId = runId;
    });

    const { cookie } = await signIn(harness);
    const res = await request(harness.server)
      .get(`/api/projects/${project.id}/artifacts/scan-data.zip`)
      .set('Host', '127.0.0.1')
      .set('Cookie', cookie)
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/zip');
    expect(res.headers['content-disposition']).toBe(`attachment; filename="Scan-data-test-scan-data-${runId}.zip"`);
    // A real zip, and big enough to hold the README and the JSON files rather than an empty archive.
    expect((res.body as Buffer).subarray(0, 2).toString('latin1')).toBe('PK');
    expect((res.body as Buffer).length).toBeGreaterThan(400);

    // A project with no run has no scan data to offer, and another project's run is not reachable through this one.
    const empty = harness.store.create({ name: 'Never built', mode: 'guided' });
    const none = await request(harness.server).get(`/api/projects/${empty.id}/artifacts/scan-data.zip`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(none.status).toBe(404);
    const foreign = await request(harness.server).get(`/api/projects/${empty.id}/reports/${runId}/scan-data.zip`).set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(foreign.status).toBe(404);

    // Every app's reports at once: a folder for the checked app, a line for the unchecked one, an index.
    const all = await request(harness.server)
      .get('/api/reports/all.zip')
      .set('Host', '127.0.0.1')
      .set('Cookie', cookie)
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(all.status).toBe(200);
    expect(all.headers['content-type']).toBe('application/zip');
    expect(all.headers['content-disposition']).toMatch(/^attachment; filename="securevibe-reports-\d{4}-\d{2}-\d{2}\.zip"$/);
    const bytes = all.body as Buffer;
    expect(bytes.subarray(0, 2).toString('latin1')).toBe('PK');
    // Read it back with SecureVibe's own zip reader: the entry names and the index text, not just the bytes.
    const unpacked = unpackZip(bytes, { maxFiles: 1000, maxTotalBytes: 50 * 1024 * 1024, maxFileBytes: 2 * 1024 * 1024 }, () => undefined);
    const paths = unpacked.files.map((f) => f.path);
    // This project is "Scan data test"; its reports folder holds the sarif written above.
    expect(paths, paths.join(', ')).toContain(`Scan-data-test-${project.id}/findings.sarif`);
    expect(paths).toContain('INDEX.md');
    expect(paths.some((p) => p.startsWith(`Never-built-${empty.id}/`))).toBe(false);
    const index = unpacked.files.find((f) => f.path === 'INDEX.md')!.data.toString();
    expect(index).toContain('- Scan data test: ');
    expect(index).toContain(`Scan-data-test-${project.id}/`);
    expect(index).toContain('Never built: not checked yet');
  });
});
