/**
 * The test runner: TAP parsing (both shapes Node emits), the evidence and findings it produces, and one real
 * run of the fixture app's own test suite through the process sandbox.
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  evidenceForTests,
  findingsForTests,
  parseTap,
  requirementIdOf,
  runTests,
  testPatterns,
  type TestResult,
} from '../../src/scanners/tests-runner/index.js';
import type { ScanContext } from '../../src/scanners/types.js';
import { buildSpecFor, MINI_APP_DIR } from './helpers/mini-app.js';

const FIXTURES = fileURLToPath(new URL('../fixtures/scanners-runtime/', import.meta.url));
const FAILING_APP_DIR = join(FIXTURES, 'failing-tests-app');

function tapFixture(name: string): string {
  return readFileSync(join(FIXTURES, 'tap', name), 'utf8');
}

function contextFor(appDir: string, projectDir: string): ScanContext {
  return {
    appDir,
    projectDir,
    runId: 'run-tests-1',
    buildSpec: buildSpecFor(),
    manifest: undefined as never,
    ignore: [],
    knowledge: undefined as never,
    log: () => {},
    abort: new AbortController().signal,
  };
}

describe('TAP parsing', () => {
  const parsed = parseTap(tapFixture('per-file.tap'));

  it('reports the leaf tests and not the suites that contain them', () => {
    expect(parsed.tests.map((t) => t.name)).toEqual([
      'V3.4.3 sends a nonce-based content security policy',
      'V3.4.4 sends X-Content-Type-Options',
      'V7.2 session identifiers > V7.2.4 issues a new identifier on sign-in',
      'V7.2 session identifiers > rejects a reused identifier',
      'V7.4.4 shows a sign-out control',
    ]);
  });

  it('records pass, fail and skip correctly', () => {
    const byName = new Map(parsed.tests.map((t) => [t.name, t]));
    expect(byName.get('V3.4.3 sends a nonce-based content security policy')?.ok).toBe(true);
    expect(byName.get('V3.4.4 sends X-Content-Type-Options')?.ok).toBe(false);
    expect(byName.get('V7.4.4 shows a sign-out control')?.skipped).toBe(true);
  });

  it('keeps the file, the duration and the failure detail', () => {
    const failed = parsed.tests.find((t) => !t.ok);
    expect(failed?.file).toBe('/app/tests/security/headers.test.ts');
    expect(failed?.durationMs).toBe(3.25);
    expect(failed?.detail).toContain('Expected values to be strictly equal');
    expect(failed?.detail).toContain('ERR_ASSERTION');
  });

  it("uses Node's own counts for the summary", () => {
    expect(parsed.summary).toMatchObject({ total: 4, passed: 2, failed: 1, skipped: 1, todo: 0 });
    expect(parsed.summary.durationMs).toBe(214.5);
    expect(parsed.empty).toBe(false);
  });

  it('reports an output with no results at all as empty', () => {
    const crashed = parseTap(tapFixture('crashed.tap'));
    expect(crashed.empty).toBe(true);
    expect(crashed.tests).toEqual([]);
  });

  it('finds the requirement id a test name evidences, including inside a suite name', () => {
    expect(requirementIdOf('V6.2.1 rejects short passwords')).toBe('V6.2.1');
    expect(requirementIdOf('C2.1.3 blocks prompt injection')).toBe('C2.1.3');
    expect(requirementIdOf('AC.4.1 records a human review')).toBe('AC.4.1');
    expect(requirementIdOf('MT-07 audit chain')).toBe('MT-07');
    expect(requirementIdOf('V7.2 session identifiers > rejects a reused identifier')).toBe('V7.2');
    expect(requirementIdOf('a test about nothing in particular')).toBeUndefined();
  });
});

describe('evidence and findings from tests', () => {
  const tests: TestResult[] = [
    { name: 'V6.2.1 refuses short passwords', ok: true, file: 'tests/security/password.test.ts', durationMs: 4 },
    { name: 'V3.4.4 sends nosniff', ok: false, file: 'tests/security/headers.test.ts', detail: 'error: expected nosniff' },
    { name: 'V7.4.4 shows a sign-out control', ok: true, skipped: true, file: 'tests/security/session.test.ts' },
    { name: 'the notes page lists notes', ok: true, file: 'tests/features/notes.test.ts' },
  ];

  it('makes one strong evidence item per test that names a requirement', () => {
    const evidence = evidenceForTests(tests, 'run-9');
    expect(evidence.map((e) => e.ref)).toEqual(['test:V6.2.1 refuses short passwords', 'test:V3.4.4 sends nosniff']);
    expect(evidence.every((e) => e.tier === 'strong' && e.type === 'test')).toBe(true);
    expect(evidence[0]?.passed).toBe(true);
    expect(evidence[1]?.passed).toBe(false);
    expect(evidence[0]?.runId).toBe('run-9');
  });

  it('never turns a skipped test into evidence', () => {
    expect(evidenceForTests(tests).some((e) => e.ref.includes('sign-out'))).toBe(false);
  });

  it('turns a failed security test into a finding a person can act on', () => {
    const findings = findingsForTests(tests);
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.source).toBe('tests');
    expect(finding.ruleId).toBe('tests.security-test-failed');
    expect(finding.severity).toBe('high');
    expect(finding.location?.file).toBe('tests/security/headers.test.ts');
    expect(finding.mappings.asvs).toEqual(['V3.4.4']);
    expect(finding.verification?.guardingTest).toBe('V3.4.4 sends nosniff');
    expect(finding.remediation.steps.length).toBeGreaterThan(0);
  });
});

describe('running the fixture app tests through the sandbox', () => {
  let projectDir: string;

  beforeAll(() => {
    projectDir = mkdtempSync(join(tmpdir(), 'securevibe-tests-runner-'));
  });

  afterAll(() => rmSync(projectDir, { recursive: true, force: true }));

  it('builds a glob pattern per extension that is actually present', () => {
    expect(testPatterns(MINI_APP_DIR, 'tests/')).toEqual(['tests/**/*.test.js']);
    expect(testPatterns(MINI_APP_DIR, 'no-such-folder/')).toEqual([]);
  });

  it('runs the suite, counts the results and turns named tests into evidence', async () => {
    const result = await runTests(contextFor(MINI_APP_DIR, projectDir));
    const details = result.details as { total: number; passed: number; failed: number; skipped: number; durationMs: number };
    expect(result.status).toBe('passed');
    expect(details.failed).toBe(0);
    expect(details.passed).toBeGreaterThanOrEqual(8);
    expect(details.skipped).toBe(1);
    expect(details.durationMs).toBeGreaterThan(0);
    expect(result.coverage).toMatchObject({ tool: 'tests', ran: true });
    expect(result.summary).toMatch(/Ran \d+ tests/);
    const refs = result.evidence.map((e) => e.ref);
    expect(refs).toContain('test:V8.2.1 every route says who is allowed to use it');
    expect(refs).toContain('test:V13.4.4 method handling > reports the methods a known path supports');
    expect(result.evidence.every((e) => e.tier === 'strong')).toBe(true);
    expect(result.findings).toEqual([]);
  }, 120_000);

  it('reports a failing security test as a finding', async () => {
    const result = await runTests(contextFor(FAILING_APP_DIR, projectDir));
    const details = result.details as { failed: number };
    expect(result.status).toBe('failed');
    expect(details.failed).toBe(1);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('tests.security-test-failed');
    expect(result.findings[0]?.title).toContain('V3.4.3 sends a content security policy');
    // The file comes back relative to the app folder, not as an absolute path from this machine.
    expect(result.findings[0]?.location?.file).toBe('tests/security/broken.test.js');
    expect(result.evidence.find((e) => e.ref.startsWith('test:V3.4.3'))?.passed).toBe(false);
  }, 120_000);

  it('skips honestly when the app has no tests folder', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'securevibe-no-tests-'));
    try {
      const result = await runTests(contextFor(empty, projectDir));
      expect(result.status).toBe('skipped');
      expect(result.coverage.ran).toBe(false);
      expect(result.coverage.reason).toMatch(/no tests\/ folder/);
      expect(result.evidence).toEqual([]);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});
