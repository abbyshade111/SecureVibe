/**
 * `unit-tests`: runs the generated app's own security + feature test suite. Skipped when `install` did not succeed.
 *
 * A test whose name starts with a requirement id becomes strong evidence for that requirement, on the strength of
 * the name alone. Each such test is therefore compared with the requirement it names (see
 * compliance/test-name-match.ts), and one that says nothing the requirement says raises a finding naming both, so a
 * person can decide whether the name or the test is wrong. The credit stands meanwhile: the comparison is words,
 * not comprehension, and about a third of what it flags is an honest test written in different words.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { StageResult } from '@shared/pipeline.js';
import { matchesRequirement, testBody } from '../../compliance/test-name-match.js';
import { runTests } from '../../integration.js';
import { findTestFiles } from '../../scanners/tests-runner/index.js';
import { requirementIdOf } from '../../scanners/tests-runner/tap.js';
import { absorbScanResult, finishStage, installFailed, skipStage, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

/** The name inside a test evidence ref ("test:V2.3.3 the list is capped" → "V2.3.3 the list is capped"). */
function testNameOf(evidence: Evidence): string | undefined {
  return evidence.type === 'test' && evidence.ref.startsWith('test:') ? evidence.ref.slice('test:'.length) : undefined;
}

/**
 * Reports test evidence whose name claims a requirement the test says nothing about. The evidence is kept: this is
 * a word comparison, and a third of what it catches is an honest test phrased differently, so the finding asks a
 * person rather than quietly costing an app its coverage.
 */
export function screenTestEvidence(ctx: PipelineCtx, evidence: Evidence[]): { kept: Evidence[]; findings: Finding[] } {
  const kept: Evidence[] = [];
  const findings: Finding[] = [];
  const reported = new Set<string>();
  /**
   * The test's own lines, so a test is judged on what it does and not only on what it is called. The run's results
   * do not say which file a test came from, so every test file is read once and searched by name.
   */
  let sources: string[] | undefined;
  const bodyOf = (name: string): string => {
    if (!ctx.appDir) return '';
    if (!sources) {
      // findTestFiles reports paths relative to the app folder.
      sources = findTestFiles(ctx.appDir, 'tests').map((file: string) => {
        try {
          return readFileSync(join(ctx.appDir, file), 'utf8');
        } catch {
          return '';
        }
      });
    }
    for (const source of sources ?? []) {
      const body = testBody(source, name);
      if (body) return body;
    }
    return '';
  };
  for (const item of evidence) {
    const name = testNameOf(item);
    const requirementId = name ? requirementIdOf(name) : undefined;
    if (!name || !requirementId) {
      kept.push(item);
      continue;
    }
    const description = ctx.frameworks.getRequirement(requirementId)?.description;
    const plain = ctx.knowledge.requirementsPlain[requirementId]?.plain;
    const text = `${name.slice(requirementId.length)}\n${bodyOf(name)}`;
    const verdict = matchesRequirement(text, description ? { description, ...(plain ? { plain } : {}) } : undefined);
    kept.push(item);
    if (verdict.match === 'supported') continue;
    ctx.log('unit-tests', `"${name}" says nothing that ${requirementId} says; worth checking whether the name or the test is wrong.`);
    if (reported.has(name)) continue;
    reported.add(name);
    findings.push({
      id: `tests-name-${createHash('sha256').update(name).digest('hex').slice(0, 8)}`,
      fingerprint: createHash('sha256').update(`tests|tests.name-does-not-match-requirement|${name}`).digest('hex'),
      source: 'tests',
      sourcesReporting: ['tests'],
      ruleId: 'tests.name-does-not-match-requirement',
      title: `A test may be named after a rule it does not check: ${name}`,
      severity: 'medium',
      severityBase: 'medium',
      priority: 'P3',
      exploitability: 'theoretical',
      confidence: 'medium',
      cwe: [],
      description:
        `The test "${name}" is named after ${requirementId}, which is about "${(description ?? '').slice(0, 160)}". Nothing in the test, its name or its lines, refers to that. ` +
        'A test named after a rule counts as proof that the rule is met, so a name that does not match can make your app look checked when it is not. ' +
        'This is a comparison of words, not of meaning, so a test written in different words can be flagged here and be perfectly good.',
      impact: `${requirementId} is still counted as verified by this test. If the name is wrong, that credit is not real, which is why this is worth a look.`,
      evidence: `Neither the test's name nor the lines of the test share a word with ${requirementId}, in the standard's wording or in SecureVibe's plain-language version of it.`,
      remediation: {
        summary: 'Rename the test after what it actually checks, or change it to check what its name claims.',
        steps: [
          `Open the test "${name}" in your app's tests folder.`,
          `Read ${requirementId} in your compliance report and decide which of the three is true: the name is wrong, the test is wrong, or both are right and only the words differ.`,
          'Rename it after the rule it really checks, add the check its name promises, or leave it alone if it is only the wording.',
        ],
        references: [],
      },
      verification: { howToConfirmFixed: 'Run the checks again; the test and the rule it names talk about the same thing.', rerunCommand: 'npm test' },
      // Deliberately mapped to no requirement. This says a test may be misnamed, not that the app breaks the rule:
      // a finding mapped to a requirement counts against it, which would let a word comparison fail a requirement
      // the app actually meets. The requirement is named in the text instead, where a person reads it.
      mappings: { asvs: [], aisvs: [], sbd: [] },
      status: 'open',
      whoCanFix: 'developer',
      introducedBy: 'unknown',
      tool: { name: 'securevibe-compliance' },
    });
  }
  return { kept, findings };
}

export async function runUnitTestsStage(ctx: PipelineCtx): Promise<StageResult> {
  if (installFailed(ctx)) {
    return skipStage(ctx, 'unit-tests', 'The packages did not install, so the tests could not run.');
  }
  const started = startStage(ctx, 'unit-tests');
  if (ctx.importedTests) return importedTestsStage(ctx, started, ctx.importedTests);
  const result = await runTests(buildScanContext(ctx, 'unit-tests'));
  // A test only counts for the requirement it names if it says something that requirement says.
  const screened = screenTestEvidence(ctx, result.evidence);
  result.evidence = screened.kept;
  result.findings = [...result.findings, ...screened.findings];
  const stage = absorbScanResult(ctx, 'unit-tests', started, result);
  const details = result.details as { total?: number; passed?: number; failed?: number; tests?: unknown } | undefined;
  if (details) ctx.acc.testResults.push(...((details.tests as PipelineCtx['acc']['testResults']) ?? []));
  return stage;
}

function importedTestsStage(ctx: PipelineCtx, started: Date, imported: NonNullable<PipelineCtx['importedTests']>): StageResult {
  const results = imported.results;
  const ran = results.filter((t) => !t.skipped);
  const failed = ran.filter((t) => !t.ok);
  ctx.acc.testResults.push(...results);
  ctx.acc.coverage.push({ tool: 'tests', ran: true, version: imported.tool, covers: `SecureVibe's own automated test suite (${imported.tool}), run just before this assessment.` });
  const summary = `Ran ${results.length} tests from ${imported.tool}: ${ran.length - failed.length} passed, ${failed.length} failed, ${results.length - ran.length} skipped.`;
  return finishStage(ctx, 'unit-tests', failed.length > 0 ? 'failed' : results.length === 0 ? 'skipped' : 'passed', summary, started, {
    details: { total: results.length, passed: ran.length - failed.length, failed: failed.length, tool: imported.tool, failures: failed.slice(0, 50).map((t) => t.name) },
  });
}
