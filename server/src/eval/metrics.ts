/**
 * Evaluation harness (docs/CONTRACTS.md "Evaluation harness"): what a golden-app build is measured on, and how a
 * result is compared with the saved baseline. Pure functions, so the comparison rules are testable without a build.
 *
 * The metrics are the facts the owner cares about: did the build finish, did each step pass, how many problems are
 * open (by seriousness), how much of ASVS/AISVS is verified, how many of the app's tests passed, and what it cost.
 */
import type { PipelineRun } from '@shared/pipeline.js';
import type { Severity } from '@shared/findings.js';

export const METRICS_VERSION = 1;

export interface StandardMetrics {
  /** Requirements automation verified (pass), out of those that apply at the target level. */
  pass: number;
  applicable: number;
  verifiedPassPercent: number;
  aiAssessed: number;
  fail: number;
}

export interface EvalMetrics {
  version: typeof METRICS_VERSION;
  case: string;
  mode: 'ai' | 'no-ai';
  runId: string;
  status: PipelineRun['status'];
  durationMs: number;
  stages: Record<string, string>;
  /** Open problems by seriousness (fixed, accepted and false-positive ones are not counted). */
  openFindings: Record<Severity, number>;
  asvs?: StandardMetrics;
  aisvs?: StandardMetrics;
  /** Skipped tests are for features the golden app does not have; they are counted so nobody reads them as failures. */
  tests: { total: number; passed: number; failed: number; skipped?: number };
  costUsd: number;
  planCoverage?: { built: number; partly: number; notBuilt: number };
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function standardMetrics(s: { summary: { counts: Record<string, number>; applicableCount: number; verifiedPassPercent: number } } | undefined): StandardMetrics | undefined {
  if (!s) return undefined;
  return {
    pass: s.summary.counts['pass'] ?? 0,
    applicable: s.summary.applicableCount,
    verifiedPassPercent: Math.round(s.summary.verifiedPassPercent * 10) / 10,
    aiAssessed: s.summary.counts['ai-assessed'] ?? 0,
    fail: s.summary.counts['fail'] ?? 0,
  };
}

export function metricsOf(run: PipelineRun, caseName: string, mode: EvalMetrics['mode']): EvalMetrics {
  const openFindings = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of run.findings) if (f.status === 'open' || f.status === 'fix-attempted') openFindings[f.severity] += 1;

  const unitTests = run.stages.find((s) => s.id === 'unit-tests');
  const details = (unitTests?.details ?? {}) as { total?: number; passed?: number; failed?: number; skipped?: number };
  const started = Date.parse(run.startedAt);
  const finished = run.finishedAt ? Date.parse(run.finishedAt) : Date.now();

  const coverage = run.planCoverage;
  return {
    version: METRICS_VERSION,
    case: caseName,
    mode,
    runId: run.id,
    status: run.status,
    durationMs: Math.max(0, finished - started),
    stages: Object.fromEntries(run.stages.map((s) => [s.id, s.status])),
    openFindings,
    ...(run.compliance ? { asvs: standardMetrics(run.compliance.asvs) } : {}),
    ...(run.compliance?.aisvs ? { aisvs: standardMetrics(run.compliance.aisvs) } : {}),
    tests: { total: details.total ?? 0, passed: details.passed ?? 0, failed: details.failed ?? 0, skipped: details.skipped ?? 0 },
    costUsd: Math.round((run.llmUsage?.estimatedCostUsd ?? 0) * 100) / 100,
    ...(coverage
      ? {
          planCoverage: {
            built: coverage.filter((c) => c.status === 'built').length,
            partly: coverage.filter((c) => c.status === 'partly').length,
            notBuilt: coverage.filter((c) => c.status === 'not-built').length,
          },
        }
      : {}),
  };
}

export interface Comparison {
  /** Things that got worse: the build should not ship with these unexplained. */
  regressions: string[];
  /** Things that got better: worth updating the baseline for. */
  improvements: string[];
  /** Differences that are neither (cost, duration, informational counts). */
  notes: string[];
}

/** How much verified coverage may drop before it counts as a regression (small rounding and ordering effects). */
export const PASS_PERCENT_TOLERANCE = 1;
/** AI-assisted builds vary from run to run; cost above this share of the baseline is flagged as a note, not a failure. */
export const COST_NOTE_RATIO = 1.5;

const STAGE_RANK: Record<string, number> = { passed: 3, skipped: 2, warning: 2, pending: 1, running: 1, failed: 0 };

export function compareMetrics(baseline: EvalMetrics, current: EvalMetrics): Comparison {
  const out: Comparison = { regressions: [], improvements: [], notes: [] };

  if (baseline.status === 'succeeded' && current.status !== 'succeeded') out.regressions.push(`The build no longer succeeds: it ended "${current.status}".`);
  else if (baseline.status !== 'succeeded' && current.status === 'succeeded') out.improvements.push(`The build now succeeds (baseline ended "${baseline.status}").`);

  for (const [stage, before] of Object.entries(baseline.stages)) {
    const after = current.stages[stage];
    if (after === undefined) {
      out.notes.push(`Step "${stage}" did not run this time (it was "${before}").`);
      continue;
    }
    const rb = STAGE_RANK[before] ?? 1;
    const ra = STAGE_RANK[after] ?? 1;
    if (ra < rb && after === 'failed') out.regressions.push(`Step "${stage}" went from ${before} to failed.`);
    else if (ra < rb) out.notes.push(`Step "${stage}" went from ${before} to ${after}.`);
    else if (ra > rb) out.improvements.push(`Step "${stage}" went from ${before} to ${after}.`);
  }
  for (const stage of Object.keys(current.stages)) if (!(stage in baseline.stages)) out.notes.push(`New step "${stage}": ${current.stages[stage]}.`);

  for (const sev of ['critical', 'high', 'medium'] as const) {
    const b = baseline.openFindings[sev] ?? 0;
    const c = current.openFindings[sev] ?? 0;
    if (c > b) out.regressions.push(`Open ${sev} problems went from ${b} to ${c}.`);
    else if (c < b) out.improvements.push(`Open ${sev} problems went from ${b} to ${c}.`);
  }
  for (const sev of ['low', 'info'] as const) {
    const b = baseline.openFindings[sev] ?? 0;
    const c = current.openFindings[sev] ?? 0;
    if (c !== b) out.notes.push(`Open ${sev} items went from ${b} to ${c}.`);
  }

  for (const std of ['asvs', 'aisvs'] as const) {
    const b = baseline[std];
    const c = current[std];
    if (!b || !c) {
      if (b && !c) out.regressions.push(`${std.toUpperCase()} was not assessed this time.`);
      continue;
    }
    const label = std.toUpperCase();
    if (c.verifiedPassPercent < b.verifiedPassPercent - PASS_PERCENT_TOLERANCE) {
      out.regressions.push(`${label} verified coverage fell from ${b.verifiedPassPercent}% to ${c.verifiedPassPercent}% (${c.pass}/${c.applicable} requirements).`);
    } else if (c.verifiedPassPercent > b.verifiedPassPercent + PASS_PERCENT_TOLERANCE) {
      out.improvements.push(`${label} verified coverage rose from ${b.verifiedPassPercent}% to ${c.verifiedPassPercent}%.`);
    }
    if (c.fail > b.fail) out.regressions.push(`${label} failing requirements went from ${b.fail} to ${c.fail}.`);
    else if (c.fail < b.fail) out.improvements.push(`${label} failing requirements went from ${b.fail} to ${c.fail}.`);
  }

  if (current.tests.failed > baseline.tests.failed) out.regressions.push(`Failing app tests went from ${baseline.tests.failed} to ${current.tests.failed}.`);
  else if (current.tests.failed < baseline.tests.failed) out.improvements.push(`Failing app tests went from ${baseline.tests.failed} to ${current.tests.failed}.`);
  if (current.tests.passed < baseline.tests.passed) out.regressions.push(`Passing app tests went from ${baseline.tests.passed} to ${current.tests.passed}.`);
  else if (current.tests.passed > baseline.tests.passed) out.improvements.push(`Passing app tests went from ${baseline.tests.passed} to ${current.tests.passed}.`);

  if (baseline.planCoverage && current.planCoverage) {
    if (current.planCoverage.notBuilt > baseline.planCoverage.notBuilt) {
      out.regressions.push(`Planned features not built went from ${baseline.planCoverage.notBuilt} to ${current.planCoverage.notBuilt}.`);
    } else if (current.planCoverage.built > baseline.planCoverage.built) {
      out.improvements.push(`Planned features built went from ${baseline.planCoverage.built} to ${current.planCoverage.built}.`);
    }
  }

  if (baseline.costUsd > 0 && current.costUsd > baseline.costUsd * COST_NOTE_RATIO) {
    out.notes.push(`Cost rose from $${baseline.costUsd.toFixed(2)} to $${current.costUsd.toFixed(2)}.`);
  }
  const slower = baseline.durationMs > 0 && current.durationMs > baseline.durationMs * 2;
  if (slower) out.notes.push(`Took ${Math.round(current.durationMs / 60000)} min (baseline ${Math.round(baseline.durationMs / 60000)} min).`);

  return out;
}

/** A short plain-language line for one case. */
export function summaryLine(m: EvalMetrics): string {
  const open = `${m.openFindings.critical}/${m.openFindings.high}/${m.openFindings.medium} open critical/high/medium`;
  const asvs = m.asvs ? `ASVS ${m.asvs.verifiedPassPercent}% verified (${m.asvs.pass}/${m.asvs.applicable})` : 'ASVS not assessed';
  const aisvs = m.aisvs ? `, AISVS ${m.aisvs.verifiedPassPercent}%` : '';
  const tests = `app tests: ${m.tests.passed} passed, ${m.tests.failed} failed, ${m.tests.skipped ?? 0} skipped of ${m.tests.total}`;
  const cost = m.mode === 'ai' ? `, $${m.costUsd.toFixed(2)}` : '';
  return `${m.status}; ${open}; ${asvs}${aisvs}; ${tests}; ${Math.round(m.durationMs / 1000)}s${cost}`;
}
