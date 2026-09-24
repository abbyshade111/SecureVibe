/**
 * Turning probe results into the two things the rest of SecureVibe consumes:
 *  - Evidence (type 'dast', tier 'strong') for the compliance engine — one item per requirement the probe proves;
 *  - Findings (source 'dast') for the security report, with remediation text taken from
 *    data/knowledge/remediation.json by probe id and the probe's own built-in wording as a fallback.
 *
 * A probe that could not run produces neither: "not attempted" is never evidence and never a finding.
 */
import { createHash } from 'node:crypto';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { RemediationEntry } from '@shared/knowledge.js';
import type { Knowledge } from '../types.js';
import type { ProbeFallback, ProbeModule, ProbeResult } from './types.js';

export const DAST_TOOL = 'securevibe-dast';
export const RERUN_COMMAND = 'npm run verify -- <app folder>';

/** Fingerprints for findings, not credentials: a fast hash is the right tool. */
function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

/** Evidence refs drop the `dast.` prefix, matching the examples in the shared Evidence schema. */
export function evidenceRef(probeId: string): string {
  return `dast:${probeId.replace(/^dast\./, '')}`;
}

let evidenceCounter = 0;
let findingCounter = 0;

/** Tests only: make ids predictable. */
export function resetDastCounters(): void {
  evidenceCounter = 0;
  findingCounter = 0;
}

function shorten(text: string | undefined, max: number): string | undefined {
  if (!text) return undefined;
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export interface DastBuildContext {
  knowledge?: Knowledge;
  runId?: string;
  /** Where the full probe output was written, for the evidence `raw.artifactPath`. */
  artifactPath?: string;
}

export function remediationFor(ctx: DastBuildContext, probeId: string): RemediationEntry | undefined {
  return ctx.knowledge?.remediation?.[probeId];
}

/**
 * One evidence item per probe result with a boolean outcome. `summary` is written for a non-technical reader:
 * it says what was checked and what happened, not how.
 */
export function evidenceForResult(result: ProbeResult, probe: ProbeModule | undefined, ctx: DastBuildContext = {}): Evidence[] {
  if (result.passed === null) return [];
  evidenceCounter += 1;
  const known = remediationFor(ctx, result.id);
  const what = result.expected || known?.title || probe?.fallback.title || result.id;
  const summary = result.passed
    ? `Checked on the running app: ${what}. It did.`
    : `Checked on the running app: ${what}. It did not — ${result.observed}.`;
  const excerptParts = [result.requestExcerpt, result.responseExcerpt].filter(Boolean).join('\n\n');
  return [
    {
      id: `E-dast-${String(evidenceCounter).padStart(4, '0')}`,
      type: 'dast',
      tier: 'strong',
      ref: evidenceRef(result.id),
      summary,
      passed: result.passed,
      tool: DAST_TOOL,
      runId: ctx.runId,
      capturedAt: new Date().toISOString(),
      raw: excerptParts ? { excerpt: shorten(excerptParts, 2048), artifactPath: ctx.artifactPath } : ctx.artifactPath ? { artifactPath: ctx.artifactPath } : undefined,
      producedBy: DAST_TOOL,
    },
  ];
}

function fallbackOf(probe: ProbeModule | undefined, result: ProbeResult): ProbeFallback {
  return (
    probe?.fallback ?? {
      title: `Runtime check failed: ${result.id}`,
      severity: 'medium',
      cwe: [],
      description: 'A runtime check against the running application did not get the result it expected.',
      impact: 'The protection this check covers may not be working.',
      fix: 'Review the request and response recorded with this finding.',
    }
  );
}

/**
 * Findings for a failed probe: one per endpoint when the probe checked many (authorization probes walk every
 * route), otherwise one for the probe itself.
 */
export function findingsForResult(result: ProbeResult, probe: ProbeModule | undefined, ctx: DastBuildContext = {}): Finding[] {
  if (result.passed !== false) return [];
  const fallback = fallbackOf(probe, result);
  const known = remediationFor(ctx, result.id);
  const override = result.findingOnFail ?? {};
  const requirementIds = result.requirementIds ?? probe?.requirementIds ?? [];
  const asvs = requirementIds.filter((id) => /^V/.test(id));
  const aisvs = requirementIds.filter((id) => /^(C\d|AC\.)/.test(id));
  const sbd = requirementIds.filter((id) => /^[A-Z]{2}-\d\d$/.test(id));

  const places =
    result.failures && result.failures.length > 0
      ? result.failures
      : [{ endpoint: result.endpoint ?? '', observed: result.observed, requestExcerpt: result.requestExcerpt, responseExcerpt: result.responseExcerpt }];

  return places.map((place) => {
    findingCounter += 1;
    const evidenceText = `Expected ${result.expected || fallback.title}. Observed: ${place.observed}.`;
    return {
      id: `dast-${String(findingCounter).padStart(4, '0')}`,
      fingerprint: sha256(`dast|${result.id}||${place.endpoint}`),
      source: 'dast',
      sourcesReporting: ['dast'],
      ruleId: result.id,
      title: known?.title ?? fallback.title,
      severity: override.severity ?? known?.severity ?? fallback.severity,
      severityBase: override.severity ?? known?.severity ?? fallback.severity,
      priority: 'P3',
      exploitability: override.exploitability ?? known?.exploitability ?? fallback.exploitability ?? 'requires-network-exposure',
      confidence: override.confidence ?? fallback.confidence ?? 'high',
      cwe: unique([...(known?.cwe ?? []), ...fallback.cwe]),
      location: {
        endpoint: place.endpoint || undefined,
        requestExcerpt: shorten(place.requestExcerpt, 2000),
        responseExcerpt: shorten(place.responseExcerpt, 2000),
      },
      description: override.description ?? known?.description ?? fallback.description,
      impact: override.impact ?? known?.impact ?? fallback.impact,
      evidence: evidenceText,
      remediation: known
        ? { summary: known.remediation.summary, steps: known.remediation.steps, example: known.remediation.example, references: known.remediation.references }
        : { summary: fallback.fix, steps: fallback.steps ?? [], references: fallback.references ?? [] },
      verification: {
        howToConfirmFixed: known?.howToConfirmFixed ?? `Re-run verification; the runtime check "${result.id}" passes when the app behaves as expected.`,
        rerunCommand: RERUN_COMMAND,
      },
      mappings: {
        asvs: unique([...asvs, ...(known?.asvs ?? [])]),
        aisvs: unique([...aisvs, ...(known?.aisvs ?? [])]),
        sbd: unique([...sbd, ...(known?.sbd ?? [])]),
      },
      status: 'open',
      whoCanFix: 'developer',
      introducedBy: 'unknown',
      tool: { name: DAST_TOOL },
    } satisfies Finding;
  });
}
