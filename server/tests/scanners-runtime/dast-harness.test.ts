/**
 * The DAST harness: starting the generated app as a real child process on a loopback port, waiting for the ready
 * line, probing it, and stopping it again — plus `runDast` from end to end.
 *
 * Binding a listening socket is not allowed in some sandboxes. When it is not, this file skips with a printed
 * note rather than failing: the probe logic itself is covered without a socket in dast-probes.test.ts.
 */
import { createServer } from 'node:net';
import { existsSync, mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppStartError, generateAppEnv, hasCertificates, resolveEntry, runDast, startApp, type DastDetails } from '../../src/scanners/dast/index.js';
import { HttpClient } from '../../src/scanners/dast/http.js';
import type { AppInstance } from '../../src/scanners/dast/types.js';
import type { ScanContext } from '../../src/scanners/types.js';
import { loadKnowledge } from '../../src/frameworks/index.js';
import { buildSpecFor, MINI_APP_DIR } from './helpers/mini-app.js';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const knowledge = loadKnowledge({ warn: () => {} });

function canListen(): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', () => resolve(false));
    server.listen(0, '127.0.0.1', () => server.close(() => resolve(true)));
  });
}

const listeningAllowed = await canListen();
if (!listeningAllowed) {
  process.stdout.write(
    '[dast-harness] skipped: this machine does not allow binding a loopback port, so the app cannot be started as a child process.\n',
  );
}

const withSockets = listeningAllowed ? describe : describe.skip;

describe('harness helpers (no socket needed)', () => {
  it('finds the start file of an app', () => {
    expect(resolveEntry(MINI_APP_DIR)).toEqual(['src/server.js']);
    const empty = mkdtempSync(join(tmpdir(), 'securevibe-empty-'));
    try {
      expect(resolveEntry(empty)).toBeUndefined();
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it('prefers the template start file when it is present', () => {
    const app = mkdtempSync(join(tmpdir(), 'securevibe-template-'));
    try {
      mkdirSync(join(app, 'src'), { recursive: true });
      writeFileSync(join(app, 'src', 'server.ts'), '');
      expect(resolveEntry(app)).toEqual(['--experimental-strip-types', 'src/server.ts']);
    } finally {
      rmSync(app, { recursive: true, force: true });
    }
  });

  it('generates fresh strong secrets and the test-mode flags for each start', () => {
    const spec = buildSpecFor();
    const a = generateAppEnv('test', spec, '/tmp/data-a', 0);
    const b = generateAppEnv('test', spec, '/tmp/data-b', 0);
    expect(a['NODE_ENV']).toBe('test');
    expect(a['SECUREVIBE_TEST_MODE']).toBe('1');
    expect(a['TLS_MODE']).toBe('off');
    expect(Buffer.from(a['SESSION_SECRET'] ?? '', 'base64').length).toBeGreaterThanOrEqual(32);
    expect(a['SECUREVIBE_TEST_PASSWORD']?.length).toBeGreaterThanOrEqual(16);
    expect(a['SESSION_SECRET']).not.toBe(b['SESSION_SECRET']);
    expect(a['SECUREVIBE_TEST_TOTP_SEED']).not.toBe(b['SECUREVIBE_TEST_TOTP_SEED']);
  });

  it('puts the production start behind a pretend TLS proxy', () => {
    const env = generateAppEnv('production', buildSpecFor(), '/tmp/data', 3000);
    expect(env['NODE_ENV']).toBe('production');
    expect(env['TLS_MODE']).toBe('proxy');
    expect(env['TRUST_PROXY_HOPS']).toBe('1');
    expect(env['SECUREVIBE_TEST_MODE']).toBeUndefined();
  });

  it('only asks for a self-signed start when the app ships a certificate', () => {
    expect(hasCertificates(MINI_APP_DIR)).toBe(false);
  });

  it('reports why an app that will not start did not start', async () => {
    const projectDir = mkdtempSync(join(tmpdir(), 'securevibe-broken-project-'));
    const broken = mkdtempSync(join(tmpdir(), 'securevibe-broken-app-'));
    try {
      mkdirSync(join(broken, 'src'), { recursive: true });
      writeFileSync(join(broken, 'src', 'server.js'), 'process.stderr.write("SESSION_SECRET is missing\\n");process.exit(1);\n');
      const error = await startApp({
        appDir: broken,
        projectDir,
        runId: 'run-harness-broken',
        phase: 'test',
        buildSpec: buildSpecFor(),
        readyTimeoutMs: 8_000,
      }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(AppStartError);
      expect((error as AppStartError).message).toMatch(/exited before it was ready/);
      expect((error as AppStartError).stderr).toContain('SESSION_SECRET is missing');
    } finally {
      rmSync(broken, { recursive: true, force: true });
      rmSync(projectDir, { recursive: true, force: true });
    }
  }, 60_000);

  it('says so when there is no start file at all', async () => {
    const projectDir = mkdtempSync(join(tmpdir(), 'securevibe-nostart-'));
    const empty = mkdtempSync(join(tmpdir(), 'securevibe-nostart-app-'));
    try {
      await expect(
        startApp({ appDir: empty, projectDir, runId: 'run-harness-3', phase: 'test', buildSpec: buildSpecFor() }),
      ).rejects.toThrow(/No start file found/);
    } finally {
      rmSync(empty, { recursive: true, force: true });
      rmSync(projectDir, { recursive: true, force: true });
    }
  });

  it('records every probe of a phase as not attempted when that start failed', async () => {
    const projectDir = mkdtempSync(join(tmpdir(), 'securevibe-nodast-'));
    const empty = mkdtempSync(join(tmpdir(), 'securevibe-nodast-app-'));
    try {
      const ctx: ScanContext = {
        appDir: empty,
        projectDir,
        runId: 'run-dast-skip',
        buildSpec: buildSpecFor(),
        manifest: undefined as never,
        ignore: [],
      toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
    toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
        knowledge,
        log: () => {},
        abort: new AbortController().signal,
      };
      const result = await runDast(ctx);
      const details = result.details as DastDetails;
      expect(result.status).toBe('skipped');
      expect(result.coverage.ran).toBe(false);
      expect(result.coverage.reason).toMatch(/No start file found/);
      expect(result.findings).toEqual([]);
      expect(result.evidence).toEqual([]);
      expect(details.counts.passed).toBe(0);
      expect(details.counts.notAttempted).toBe(details.probes.length);
      expect(details.probes.every((p) => p.passed === null && p.reason)).toBe(true);
      expect(result.summary).toMatch(/could not be started/);
    } finally {
      rmSync(empty, { recursive: true, force: true });
      rmSync(projectDir, { recursive: true, force: true });
    }
  }, 60_000);
});

withSockets('starting the fixture app as a child process', () => {
  let projectDir: string;
  let app: AppInstance | undefined;

  beforeAll(() => {
    projectDir = mkdtempSync(join(tmpdir(), 'securevibe-harness-'));
  });

  afterAll(async () => {
    await app?.stop();
    rmSync(projectDir, { recursive: true, force: true });
  });

  it('waits for the ready line and answers requests', async () => {
    app = await startApp({
      appDir: MINI_APP_DIR,
      projectDir,
      runId: 'run-harness-1',
      phase: 'test',
      buildSpec: buildSpecFor(),
      extraReadPaths: [REPO_ROOT],
    });
    expect(app.port).toBeGreaterThan(0);
    expect(app.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(app.pid).toBeGreaterThan(0);
    expect(existsSync(app.dataDir)).toBe(true);

    const http = new HttpClient(app.baseUrl);
    const health = await http.get('/healthz');
    expect(health.status).toBe(200);
    expect(health.json<{ status: string }>()?.status).toBe('ok');

    const routes = await http.get('/__securevibe/routes');
    expect(routes.status).toBe(200);
  }, 120_000);

  it('stops the app and removes its throw-away data folder', async () => {
    const dataDir = app!.dataDir;
    await app!.stop();
    const stopped = app!;
    app = undefined;
    expect(existsSync(dataDir)).toBe(false);
    let alive = true;
    try {
      process.kill(stopped.pid!, 0);
    } catch {
      alive = false;
    }
    expect(alive).toBe(false);
  }, 60_000);

});

withSockets('runDast end to end', () => {
  let projectDir: string;

  beforeAll(() => {
    projectDir = mkdtempSync(join(tmpdir(), 'securevibe-rundast-'));
  });

  afterAll(() => rmSync(projectDir, { recursive: true, force: true }));

  it('starts the app twice, runs every probe and reports evidence, findings and coverage', async () => {
    const ctx: ScanContext = {
      appDir: MINI_APP_DIR,
      projectDir,
      runId: 'run-dast-1',
      buildSpec: buildSpecFor(),
      manifest: undefined as never,
      ignore: [],
      toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
    toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
      knowledge,
      log: () => {},
      abort: new AbortController().signal,
    };
    const result = await runDast(ctx, { extraReadPaths: [REPO_ROOT] });
    const details = result.details as DastDetails;

    expect(details.phases.find((p) => p.phase === 'test')?.started).toBe(true);
    expect(details.phases.find((p) => p.phase === 'production')?.started).toBe(true);
    expect(details.phases.find((p) => p.phase === 'selfsigned')?.started).toBe(false);
    expect(details.seededRoles).toEqual(expect.arrayContaining(['admin', 'member']));
    expect(details.routesProbed).toBeGreaterThan(10);
    expect(details.counts.passed).toBeGreaterThan(20);
    expect(details.counts.failed).toBe(0);

    expect(result.coverage).toMatchObject({ tool: 'dast', ran: true });
    expect(result.coverage.covers).toMatch(/Starts your app privately/);
    expect(result.status).toBe('passed');
    expect(result.summary).toMatch(/runtime checks/);

    // Evidence exists for every probe that reached a verdict, and for none that did not.
    const verdicts = details.probes.filter((p) => p.passed !== null);
    expect(result.evidence).toHaveLength(verdicts.length);
    expect(result.evidence.every((e) => e.type === 'dast' && e.tier === 'strong')).toBe(true);
    expect(result.findings).toEqual([]);
  }, 300_000);
});
