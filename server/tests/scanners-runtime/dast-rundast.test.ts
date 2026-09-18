/**
 * `runDast` from end to end: both app starts, every probe, and the evidence, findings and coverage row it hands
 * to the pipeline. The app runs inside this process (see helpers/loopback.ts), so the same path is covered where
 * binding a loopback port is not allowed; dast-harness.test.ts covers the real child-process start.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadKnowledge } from '../../src/frameworks/index.js';
import { runDast, type DastDetails } from '../../src/scanners/dast/index.js';
import type { AppInstance, ProbePhase } from '../../src/scanners/dast/types.js';
import type { HttpClient } from '../../src/scanners/dast/http.js';
import type { ScanContext, ScanResult } from '../../src/scanners/types.js';
import { LoopbackHttpClient } from './helpers/loopback.js';
import { buildSpecFor, MINI_APP_DIR, TEST_PASSWORD } from './helpers/mini-app.js';
import { randomBytes } from 'node:crypto';
import { base32Encode } from '../../src/scanners/dast/totp.js';

import { createApp } from '../fixtures/scanners-runtime/mini-app/src/app.js';

const knowledge = loadKnowledge({ warn: () => {} });

describe('runDast', () => {
  let projectDir: string;
  let result: ScanResult;
  let details: DastDetails;
  const clients = new Map<string, LoopbackHttpClient>();

  beforeAll(async () => {
    projectDir = mkdtempSync(join(tmpdir(), 'securevibe-rundast-inproc-'));
    const ctx: ScanContext = {
      appDir: MINI_APP_DIR,
      projectDir,
      runId: 'run-dast-inproc',
      buildSpec: buildSpecFor(),
      manifest: undefined as never,
      ignore: [],
      toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
    toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
      knowledge,
      log: () => {},
      abort: new AbortController().signal,
    };

    const start = async (phase: ProbePhase): Promise<AppInstance> => {
      const dataDir = mkdtempSync(join(tmpdir(), `securevibe-${phase}-`));
      const env: Record<string, string> = {
        NODE_ENV: phase === 'test' ? 'test' : 'production',
        DATA_DIR: dataDir,
        TLS_MODE: phase === 'test' ? 'off' : 'proxy',
        TRUST_PROXY_HOPS: phase === 'test' ? '0' : '1',
        SECUREVIBE_TEST_PASSWORD: TEST_PASSWORD,
        SECUREVIBE_TEST_TOTP_SEED: base32Encode(randomBytes(20)),
        ...(phase === 'test' ? { SECUREVIBE_TEST_MODE: '1' } : {}),
      };
      const client = new LoopbackHttpClient(createApp(env));
      clients.set(phase, client);
      return {
        phase,
        baseUrl: client.baseUrl,
        port: 8080,
        pid: process.pid,
        dataDir,
        env,
        tlsMode: phase === 'test' ? 'off' : 'proxy',
        sandboxMode: 'none',
        output: () => ({ stdout: '', stderr: '' }),
        stop: async () => {
          client.close();
          rmSync(dataDir, { recursive: true, force: true });
        },
      };
    };

    result = await runDast(ctx, { start, client: (app) => clients.get(app.phase) as HttpClient });
    details = result.details as DastDetails;
  }, 180_000);

  afterAll(() => {
    for (const client of clients.values()) client.close();
    rmSync(projectDir, { recursive: true, force: true });
  });

  it('starts the app in test mode and again in production mode', () => {
    expect(details.phases.find((p) => p.phase === 'test')?.started).toBe(true);
    expect(details.phases.find((p) => p.phase === 'production')?.started).toBe(true);
  });

  it('skips the self-signed start with a reason a person can read', () => {
    const tls = details.phases.find((p) => p.phase === 'selfsigned');
    expect(tls?.started).toBe(false);
    expect(tls?.reason).toMatch(/not configured to serve HTTPS itself/);
    expect(details.probes.find((p) => p.id === 'dast.tls.min-version')?.passed).toBeNull();
  });

  it('reports which roles it signed in and how many routes it walked', () => {
    expect(details.seededRoles.sort()).toEqual(['admin', 'member', 'staff']);
    expect(details.routesProbed).toBeGreaterThan(10);
  });

  it('finds no problems in the fixture app and says so in plain language', () => {
    const failed = details.probes.filter((p) => p.passed === false);
    expect(failed.map((p) => `${p.id}: ${p.observed}`)).toEqual([]);
    expect(result.findings).toEqual([]);
    expect(result.status).toBe('passed');
    expect(result.summary).toMatch(/^Ran \d+ runtime checks against your app: \d+ passed/);
  });

  it('produces one strong evidence item per probe that reached a verdict, and none for the rest', () => {
    const verdicts = details.probes.filter((p) => p.passed !== null);
    expect(verdicts.length).toBeGreaterThan(30);
    expect(result.evidence).toHaveLength(verdicts.length);
    expect(result.evidence.every((e) => e.type === 'dast' && e.tier === 'strong' && e.tool === 'securevibe-dast')).toBe(true);
    const refs = new Set(result.evidence.map((e) => e.ref));
    expect(refs.has('dast:leak.test-endpoints-absent')).toBe(true);
    expect(refs.has('dast:cookie.secure-host-prefix')).toBe(true);
  });

  it('fills the tool coverage row the security report prints', () => {
    expect(result.coverage.tool).toBe('dast');
    expect(result.coverage.ran).toBe(true);
    expect(result.coverage.covers).toMatch(/Starts your app privately/);
    expect(result.coverage.reason).toBeUndefined();
  });

  it('reports a real problem as a finding with remediation from the knowledge base', async () => {
    // The same fixture with its security headers switched off.
    const ctx: ScanContext = {
      appDir: MINI_APP_DIR,
      projectDir,
      runId: 'run-dast-broken',
      buildSpec: buildSpecFor(),
      manifest: undefined as never,
      ignore: [],
      toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
    toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
      knowledge,
      log: () => {},
      abort: new AbortController().signal,
    };
    const broken: LoopbackHttpClient[] = [];
    const start = async (phase: ProbePhase): Promise<AppInstance> => {
      const dataDir = mkdtempSync(join(tmpdir(), `securevibe-broken-${phase}-`));
      const env: Record<string, string> = {
        NODE_ENV: phase === 'test' ? 'test' : 'production',
        DATA_DIR: dataDir,
        TLS_MODE: 'off',
        TRUST_PROXY_HOPS: '0',
        SECUREVIBE_TEST_PASSWORD: TEST_PASSWORD,
        SECUREVIBE_TEST_TOTP_SEED: base32Encode(randomBytes(20)),
        ...(phase === 'test' ? { SECUREVIBE_TEST_MODE: '1' } : {}),
      };
      const app = createApp(env);
      // Strip the policy header on the way out, the way a careless change to the app would.
      const withoutCsp: import('node:http').RequestListener = (req, res) => {
        const setHeader = res.setHeader.bind(res);
        res.setHeader = ((name: string, value: never) =>
          name.toLowerCase() === 'content-security-policy' ? res : setHeader(name, value)) as typeof res.setHeader;
        app(req, res);
      };
      const client = new LoopbackHttpClient(withoutCsp);
      broken.push(client);
      return {
        phase,
        baseUrl: client.baseUrl,
        port: 8080,
        pid: process.pid,
        dataDir,
        env,
        tlsMode: 'off',
        sandboxMode: 'none',
        output: () => ({ stdout: '', stderr: '' }),
        stop: async () => {
          client.close();
          rmSync(dataDir, { recursive: true, force: true });
        },
      };
    };

    const brokenResult = await runDast(ctx, { start, client: (app) => broken[app.phase === 'test' ? 0 : 1] as HttpClient });
    const csp = brokenResult.findings.find((f) => f.ruleId === 'dast.headers.csp');
    expect(csp, JSON.stringify(brokenResult.findings.map((f) => f.ruleId))).toBeDefined();
    expect(csp?.source).toBe('dast');
    expect(csp?.severity).toBe('high');
    expect(csp?.title).toBe(knowledge.remediation['dast.headers.csp']?.title);
    expect(csp?.remediation.steps.length).toBeGreaterThan(0);
    expect(csp?.location?.responseExcerpt).toBeTruthy();
    expect(brokenResult.status).toBe('failed');
    const evidence = brokenResult.evidence.find((e) => e.ref === 'dast:headers.csp');
    expect(evidence?.passed).toBe(false);
  }, 180_000);
});
