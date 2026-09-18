/**
 * The second app start the contract requires (CONTRACTS §2): production mode behind a pretend TLS proxy.
 * These checks only mean something when test mode is off — the test endpoints must be gone, the readiness
 * endpoint must answer, and the session cookie must be Secure and __Host- prefixed.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runProbes } from '../../src/scanners/dast/runner.js';
import { probesForPhase } from '../../src/scanners/dast/probes/index.js';
import type { ProbeResult } from '../../src/scanners/dast/types.js';
import { startMiniApp, type MiniAppHandle } from './helpers/mini-app.js';

describe('runtime probes against the fixture app (production mode behind a TLS proxy)', () => {
  let handle: MiniAppHandle;
  let results: Map<string, ProbeResult>;

  beforeAll(async () => {
    handle = await startMiniApp({ phase: 'production', tlsMode: 'proxy', trustProxyHops: 1 });
    results = new Map((await runProbes(handle.ctx)).map((r) => [r.id, r]));
  }, 60_000);

  afterAll(() => handle?.close());

  it('runs only the production-phase probes', () => {
    expect([...results.keys()].sort()).toEqual(probesForPhase('production').map((p) => p.id).sort());
  });

  it('confirms the test-mode endpoints are gone', () => {
    const probe = results.get('dast.leak.test-endpoints-absent');
    expect(probe?.passed, JSON.stringify(probe)).toBe(true);
  });

  it('confirms the readiness endpoint answers from this computer', () => {
    expect(results.get('dast.health.readyz')?.passed).toBe(true);
  });

  it('confirms the session cookie is Secure with the __Host- prefix', () => {
    const probe = results.get('dast.cookie.secure-host-prefix');
    expect(probe?.passed, JSON.stringify(probe)).toBe(true);
    expect(probe?.observed).toContain('__Host-sid');
  });

  it('confirms Strict-Transport-Security is at least a year', () => {
    const probe = results.get('dast.headers.hsts');
    expect(probe?.passed, JSON.stringify(probe)).toBe(true);
    expect(probe?.observed).toContain('31536000');
  });

  it('fails the test-endpoint probe when the endpoints are still mounted', async () => {
    // Same app, but started in test mode: the probe must report a finding, not a pass.
    const leaky = await startMiniApp({ phase: 'test' });
    try {
      const probe = probesForPhase('production').find((p) => p.id === 'dast.leak.test-endpoints-absent');
      const outcome = await probe!.run({ ...leaky.ctx, phase: 'production' });
      expect(outcome.passed).toBe(false);
      expect(outcome.observed).toMatch(/__securevibe\/routes answered 200/);
    } finally {
      leaky.close();
    }
  });
});
