/**
 * The `unit-tests` stage: runs the generated app's own test suite (`node --experimental-strip-types --test
 * --test-reporter=tap tests/`) in the sandbox with a throw-away DATA_DIR, parses the TAP output, and turns it into
 * evidence and findings.
 *
 * Tests are the strongest evidence SecureVibe has, so a test whose name starts with a requirement id becomes one
 * evidence item for that requirement (`test:<name>`, tier strong) — passing or failing. A failed test in
 * `tests/security/` (or any failed test naming a requirement) also becomes a finding, because a protection the
 * template promised is not working.
 */
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { isAbsolute, join, relative } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { Finding, Severity } from '@shared/findings.js';
import type { ToolCoverage } from '@shared/pipeline.js';
import { removeDir, runNode, type ProcessResult } from '../../pipeline/process.js';
import type { ScanContext, ScanResult, ScanStatus } from '../types.js';
import { parseTap, requirementIdOf, type TestResult } from './tap.js';

export type { TestResult, TapSummary, TapParseResult } from './tap.js';
export { parseTap, requirementIdOf } from './tap.js';

export const TESTS_COVERS =
  "Runs the app's own automated tests, including the built-in security tests for sign-in, permissions, forms, headers and error handling.";
export const TESTS_TIMEOUT_MS = 10 * 60_000;
export const RERUN_COMMAND = 'npm test';
export const SECURITY_TEST_DIR = 'tests/security';

export interface TestsDetails {
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  durationMs: number;
  tests: TestResult[];
  /** Exit code of the test process; null when it was killed. */
  exitCode: number | null;
  timedOut: boolean;
  sandboxMode: string;
}

export interface RunTestsOptions {
  /** Test folder relative to the app, default `tests/`. */
  testDir?: string;
  timeoutMs?: number;
  /** Skip the Node permission model (used by this module's own tests). */
  sandbox?: boolean;
  extraReadPaths?: string[];
  extraEnv?: Record<string, string>;
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function isSecurityTest(test: TestResult): boolean {
  return (test.file ?? '').replace(/\\/g, '/').includes(SECURITY_TEST_DIR) || requirementIdOf(test.name) !== undefined;
}

/** Test files under a folder, as paths relative to the app. */
export function findTestFiles(appDir: string, testDir: string): string[] {
  const root = join(appDir, testDir.replace(/\/$/, ''));
  const found: string[] = [];
  const walk = (current: string, depth: number): void => {
    if (depth > 6) return;
    let entries: string[];
    try {
      entries = readdirSync(current);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(current, entry);
      let isDir = false;
      try {
        isDir = statSync(full).isDirectory();
      } catch {
        continue;
      }
      if (isDir) {
        if (entry !== 'node_modules') walk(full, depth + 1);
        continue;
      }
      if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(entry)) found.push(relative(appDir, full).replace(/\\/g, '/'));
    }
  };
  walk(root, 0);
  return found.sort();
}

/** Node takes glob patterns, not a folder, so a pattern is built per extension that is actually present. */
export function testPatterns(appDir: string, testDir: string): string[] {
  const clean = testDir.replace(/\/$/, '');
  const extensions = new Set(findTestFiles(appDir, testDir).map((f) => /\.(test|spec)\.([cm]?[jt]sx?)$/.exec(f)?.[2] ?? ''));
  return [...extensions].filter(Boolean).map((ext) => `${clean}/**/*.test.${ext}`);
}

function relativeFile(appDir: string, file: string | undefined): string | undefined {
  if (!file) return undefined;
  const clean = isAbsolute(file) ? relative(appDir, file) : file;
  return clean.replace(/\\/g, '/').replace(/^\.\//, '');
}

let evidenceCounter = 0;
let findingCounter = 0;

/** One evidence item per test that names a requirement (CONTRACTS §9.4: tests are strong evidence). */
export function evidenceForTests(tests: TestResult[], runId?: string): Evidence[] {
  const out: Evidence[] = [];
  for (const test of tests) {
    if (!requirementIdOf(test.name)) continue;
    if (test.skipped) continue;
    evidenceCounter += 1;
    out.push({
      id: `E-test-${String(evidenceCounter).padStart(4, '0')}`,
      type: 'test',
      tier: 'strong',
      ref: `test:${test.name}`,
      summary: test.ok
        ? `The app's own test "${test.name}" passed.`
        : `The app's own test "${test.name}" failed${test.detail ? `: ${test.detail}` : ''}.`,
      passed: test.ok,
      tool: 'node:test',
      runId,
      capturedAt: new Date().toISOString(),
      location: test.file ? { file: test.file } : undefined,
      producedBy: 'node:test',
    });
  }
  return out;
}

/** A failed security test becomes a finding: something the app promises to do is not working. */
export function findingsForTests(tests: TestResult[]): Finding[] {
  const out: Finding[] = [];
  for (const test of tests) {
    if (test.ok || test.skipped || !isSecurityTest(test)) continue;
    const requirement = requirementIdOf(test.name);
    findingCounter += 1;
    const severity: Severity = requirement ? 'high' : 'medium';
    out.push({
      id: `tests-${String(findingCounter).padStart(4, '0')}`,
      fingerprint: sha256(`tests|tests.security-test-failed|${test.file ?? ''}|${test.name}`),
      source: 'tests',
      sourcesReporting: ['tests'],
      ruleId: 'tests.security-test-failed',
      title: `A built-in security test is failing: ${test.name}`,
      severity,
      severityBase: severity,
      priority: 'P3',
      exploitability: 'requires-network-exposure',
      confidence: 'high',
      cwe: [],
      location: { file: test.file },
      description: `The test "${test.name}" checks a protection your app is supposed to have, and it did not pass.`,
      impact: 'A protection that was tested and is now failing is a protection you cannot rely on.',
      evidence: test.detail ? `The test runner reported: ${test.detail}` : 'The test runner reported a failure with no further detail.',
      remediation: {
        summary: 'Run the app\'s tests, read the failure, and restore the behavior the test expects.',
        steps: [
          'Open a terminal in your app folder.',
          'Run `npm test` and find this test in the output.',
          'Fix the code so the test passes again — do not change the test.',
        ],
        references: [],
      },
      verification: { howToConfirmFixed: 'Re-run the tests; this test passes.', rerunCommand: RERUN_COMMAND, guardingTest: test.name },
      mappings: { asvs: requirement && requirement.startsWith('V') ? [requirement] : [], aisvs: requirement && /^(C\d|AC\.)/.test(requirement) ? [requirement] : [], sbd: requirement && /^[A-Z]{2}-\d\d$/.test(requirement) ? [requirement] : [] },
      status: 'open',
      whoCanFix: 'developer',
      introducedBy: 'unknown',
      tool: { name: 'node:test' },
    });
  }
  return out;
}

/** Finding used when the suite could not run at all (missing folder, crash, timeout). */
function suiteErrorFinding(reason: string, detail: string): Finding {
  findingCounter += 1;
  return {
    id: `tests-${String(findingCounter).padStart(4, '0')}`,
    fingerprint: sha256(`tests|tests.suite-did-not-run||${reason}`),
    source: 'tests',
    sourcesReporting: ['tests'],
    ruleId: 'tests.suite-did-not-run',
    title: 'The app\'s test suite could not be run',
    severity: 'medium',
    severityBase: 'medium',
    priority: 'P3',
    exploitability: 'theoretical',
    confidence: 'high',
    cwe: [],
    description: `The built-in tests are the main proof that your app's protections work, and they could not be run: ${reason}`,
    impact: 'Without the tests, several security requirements can only be marked "not verified" in your report.',
    evidence: detail.slice(0, 1500) || 'No output was produced.',
    remediation: {
      summary: 'Install the packages and run the tests by hand to see the error.',
      steps: ['Open a terminal in your app folder.', 'Run `npm install`.', 'Run `npm test` and read the first error.'],
      references: [],
    },
    verification: { howToConfirmFixed: 'Re-run verification; the test stage reports a number of passing tests.', rerunCommand: RERUN_COMMAND },
    mappings: { asvs: [], aisvs: [], sbd: ['MT-03'] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'unknown',
    tool: { name: 'node:test' },
  };
}

function statusFor(details: TestsDetails, ran: boolean): ScanStatus {
  if (!ran) return 'skipped';
  if (details.failed > 0) return 'failed';
  if (details.total === 0) return 'warning';
  return 'passed';
}

/** Runs the generated app's test suite and reports it. Never throws: a broken suite is a result, not a crash. */
export async function runTests(ctx: ScanContext, opts: RunTestsOptions = {}): Promise<ScanResult> {
  const testDir = opts.testDir ?? 'tests/';
  const absoluteTestDir = join(ctx.appDir, testDir.replace(/\/$/, ''));
  const coverage: ToolCoverage = { tool: 'tests', ran: false, version: 'node:test', covers: TESTS_COVERS };

  if (!existsSync(absoluteTestDir)) {
    const reason = `skipped: this app has no ${testDir} folder`;
    return {
      findings: [],
      evidence: [],
      coverage: { ...coverage, reason },
      details: { total: 0, passed: 0, failed: 0, skipped: 0, durationMs: 0, tests: [], exitCode: null, timedOut: false, sandboxMode: 'none' } satisfies TestsDetails,
      status: 'skipped',
      summary: `No tests were run: your app has no ${testDir} folder.`,
    };
  }

  const testFiles = findTestFiles(ctx.appDir, testDir);
  const patterns = testPatterns(ctx.appDir, testDir);
  if (patterns.length === 0) {
    const reason = `skipped: no test files were found in ${testDir}`;
    return {
      findings: [],
      evidence: [],
      coverage: { ...coverage, reason },
      details: { total: 0, passed: 0, failed: 0, skipped: 0, durationMs: 0, tests: [], exitCode: null, timedOut: false, sandboxMode: 'none' } satisfies TestsDetails,
      status: 'skipped',
      summary: `No tests were run: there are no test files in ${testDir}.`,
    };
  }

  const tmpRoot = join(ctx.projectDir, 'tmp');
  mkdirSync(tmpRoot, { recursive: true });
  const dataDir = join(tmpRoot, `tests-${randomBytes(4).toString('hex')}`);
  mkdirSync(dataDir, { recursive: true });

  let result: ProcessResult;
  try {
    result = await runNode(['--experimental-strip-types', '--test', '--test-reporter=tap', ...patterns], {
      cwd: ctx.appDir,
      projectDir: ctx.projectDir,
      runId: ctx.runId,
      timeoutMs: opts.timeoutMs ?? TESTS_TIMEOUT_MS,
      env: {
        NODE_ENV: 'test',
        DATA_DIR: dataDir,
        LOG_LEVEL: 'silent',
        // `node --test` runs each test file in its own process, and a generated app's suite has around thirty of
        // them, each stripping types from and compiling the same hundred or so modules. They share this cache, so
        // that work happens once instead of thirty times. It is a cache of compiler output and nothing else: the
        // same code runs, and it lives inside the one folder the tests are allowed to write to, so it is thrown
        // away with the run rather than carried between them.
        NODE_COMPILE_CACHE: join(dataDir, 'compile-cache'),
        ...(opts.extraEnv ?? {}),
      },
      // node --test runs each file in a child process, so the permission model must allow that.
      permission:
        opts.sandbox === false
          ? undefined
          : { read: [ctx.appDir, ...(opts.extraReadPaths ?? [])], write: [dataDir], allowChildProcess: true, allowWorker: true },
      abort: ctx.abort,
      onStdout: () => {},
    });
  } catch (err) {
    const reason = `skipped: the test runner could not be started (${(err as Error).message})`;
    removeDir(dataDir);
    return {
      findings: [suiteErrorFinding('the test runner could not be started', (err as Error).message)],
      evidence: [],
      coverage: { ...coverage, reason },
      details: { total: 0, passed: 0, failed: 0, skipped: 0, durationMs: 0, tests: [], exitCode: null, timedOut: false, sandboxMode: 'none' } satisfies TestsDetails,
      status: 'skipped',
      summary: 'The tests could not be run on this computer.',
    };
  }
  removeDir(dataDir);

  // The raw output is kept next to the stage log, so a failure can be looked into without running the tests again.
  if (ctx.runId) {
    try {
      const stagesDir = join(ctx.projectDir, 'pipeline', ctx.runId, 'stages');
      mkdirSync(stagesDir, { recursive: true });
      writeFileSync(join(stagesDir, 'unit-tests.tap'), [result.stdout, result.stderr ? `\n# --- stderr ---\n${result.stderr}` : ''].join(''), { mode: 0o600 });
    } catch {
      // the parsed results below are what matter; the raw copy is a convenience
    }
  }

  const parsed = parseTap(result.stdout);
  // Node only names the file of a test that failed; when the whole suite is one file, the rest belong to it too.
  const onlyFile = testFiles.length === 1 ? testFiles[0] : undefined;
  for (const test of parsed.tests) test.file = relativeFile(ctx.appDir, test.file) ?? onlyFile;
  const details: TestsDetails = {
    total: parsed.summary.total,
    passed: parsed.summary.passed,
    failed: parsed.summary.failed,
    skipped: parsed.summary.skipped,
    durationMs: parsed.summary.durationMs ?? result.durationMs,
    tests: parsed.tests,
    exitCode: result.code,
    timedOut: result.timedOut,
    sandboxMode: result.sandboxMode,
  };

  const findings = findingsForTests(parsed.tests);
  const evidence = evidenceForTests(parsed.tests, ctx.runId);

  if (parsed.empty) {
    const reason = result.timedOut
      ? 'the tests were stopped because they took too long'
      : `the test runner produced no results (exit code ${result.code ?? 'unknown'})`;
    const detail = [result.stderr, result.stdout].filter(Boolean).join('\n').trim();
    ctx.log(`[tests] ${reason}`);
    return {
      findings: [...findings, suiteErrorFinding(reason, detail)],
      evidence,
      coverage: { ...coverage, ran: false, reason: `skipped: ${reason}` },
      details,
      status: 'skipped',
      summary: `The tests did not run: ${reason}.`,
    };
  }

  const summary = `Ran ${details.total} tests from your app: ${details.passed} passed, ${details.failed} failed${details.skipped ? `, ${details.skipped} skipped` : ''}.`;
  ctx.log(`[tests] ${summary}`);
  return {
    findings,
    evidence,
    coverage: { ...coverage, ran: true, reason: result.timedOut ? 'the suite was stopped at the time limit; results are partial' : undefined },
    details,
    status: statusFor(details, true),
    summary,
  };
}
