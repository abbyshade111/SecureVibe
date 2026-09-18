import { describe, expect, it } from 'vitest';
import { evaluateManifestControls } from '../../src/compliance/manifest-check.js';
import { buildSpecFixture, makeManifestCheckContext } from '../fixtures/compliance/context.js';
import { manifestFixture } from '../fixtures/compliance/manifest.js';

function resultFor(results: Awaited<ReturnType<typeof evaluateManifestControls>>, id: string) {
  const r = results.find((x) => x.controlId === id);
  if (!r) throw new Error(`no result for ${id}`);
  return r;
}

describe('evaluateManifestControls', () => {
  it('never credits a control from a passing file-contains check alone', async () => {
    const ctx = makeManifestCheckContext();
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-FILEONLY-01');
    expect(r.expected).toBe(true);
    expect(r.checks[0]?.passed).toBe(true); // the file really does contain the pattern
    expect(r.passed).toBe(false); // but nothing credits it
    expect(r.creditedBy).toEqual([]);
  });

  it('credits a control once a named test passes, alongside its supporting file-contains check', async () => {
    const ctx = makeManifestCheckContext({ testResults: [{ name: 'V6.2.1 rejects short passwords', ok: true }] });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-AUTH-01');
    expect(r.passed).toBe(true);
    expect(r.creditedBy).toContain('test');
    expect(r.evidence.some((e) => e.type === 'test' && e.passed)).toBe(true);
  });

  it('fails the whole control when the named test fails, even though the supporting check still passes', async () => {
    const ctx = makeManifestCheckContext({ testResults: [{ name: 'V6.2.1 rejects short passwords', ok: false }] });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-AUTH-01');
    expect(r.passed).toBe(false);
    const fileCheck = r.checks.find((c) => c.check.type === 'file-contains');
    expect(fileCheck?.passed).toBe(true); // the supporting check alone is not enough to save it
  });

  it('credits a control from a passing runtime probe', async () => {
    const ctx = makeManifestCheckContext({ probeResults: [{ id: 'dast.headers.csp', passed: true, observed: 'CSP header present' }] });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-HEADERS-01');
    expect(r.passed).toBe(true);
    expect(r.creditedBy).toContain('dast');
  });

  it('a probe that could not run (passed: null) never credits and is reported as skipped, not failed', async () => {
    const ctx = makeManifestCheckContext({ probeResults: [{ id: 'dast.headers.csp', passed: null, reason: 'the runtime scan did not complete' }] });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-HEADERS-01');
    expect(r.passed).toBe(false);
    expect(r.skippedReason).toBeTruthy();
  });

  it('credits a control from a named AST check plus a clean sast-clean check', async () => {
    const ctx = makeManifestCheckContext({ astResults: { 'db-wrapper-only': { passed: true, detail: 'every query goes through db.ts' } } });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-DB-01');
    expect(r.passed).toBe(true);
    expect(r.creditedBy).toContain('ast');
  });

  it('credits a control from a passing config-value check', async () => {
    const ctx = makeManifestCheckContext({ configResults: [{ id: 'config.secrets-strength', passed: true, detail: 'all secrets are strong' }] });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-SECRETS-01');
    expect(r.passed).toBe(true);
    expect(r.creditedBy).toContain('config-value');
  });

  it('credits a doc-generated control but flags it docOnly (weak evidence, not a code check)', async () => {
    const ctx = makeManifestCheckContext({ docsMatch: { 'docs/validation.md': true } });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-VALIDATION-02');
    expect(r.passed).toBe(true);
    expect(r.docOnly).toBe(true);
  });

  it('marks a feature-gated control as not expected when the feature is off, and runs no checks', async () => {
    const ctx = makeManifestCheckContext({ buildSpec: buildSpecFixture({ ai: false }) });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-AI-01');
    expect(r.expected).toBe(false);
    expect(r.checks).toEqual([]);
    expect(r.passed).toBe(false);
  });

  it('credits the AI control once the feature is on and its test passes', async () => {
    const ctx = makeManifestCheckContext({
      buildSpec: buildSpecFixture({ ai: true }),
      testResults: [{ name: 'C2.1.1 normalises input', ok: true }],
    });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-AI-01');
    expect(r.expected).toBe(true);
    expect(r.passed).toBe(true);
  });

  it('marks a TLS-mode-gated control as not expected outside its TLS mode', async () => {
    const ctx = makeManifestCheckContext({ buildSpec: buildSpecFixture({ tlsMode: 'off' }) });
    const results = await evaluateManifestControls(manifestFixture, ctx);
    const r = resultFor(results, 'TPL-TLS-01');
    expect(r.expected).toBe(false);
  });
});
