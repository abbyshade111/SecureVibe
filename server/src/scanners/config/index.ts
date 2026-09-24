/**
 * The config scanner (CONTRACTS §4): runs every `config.*` check against the generated app's
 * configuration files and turns each outcome into Evidence (`type: 'config'`, `tier: 'medium'`), plus a
 * Finding when it fails.
 */
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import { buildEvidence, buildFinding, countBySeverityText, statusFromFindings } from '../sast/findings.js';
import type { ScanContext, ScanResult, Scanner } from '../types.js';
import { CONFIG_CHECKS } from './checks.js';
import { DOC_CHECKS } from './docs-checks.js';

/** Everything the config stage runs: the app's settings, then the documents that describe them. */
export const ALL_CONFIG_CHECKS = [...CONFIG_CHECKS, ...DOC_CHECKS];

export const CONFIG_TOOL = { name: 'securevibe-config', version: '1.0.0' };

export const runConfig: Scanner = async (ctx) => {
  ctx.log('Checking configuration and documentation: environment files, secrets, TLS settings, protected files, and whether the generated documents still match the app…');
  const findings: Finding[] = [];
  const evidence: Evidence[] = [];

  const notApplicable: string[] = [];
  const notApplicableWhy = new Map<string, number>();
  for (const check of ALL_CONFIG_CHECKS) {
    if (ctx.abort.aborted) break;
    // A check with nothing to say about this app is recorded as not applicable, never as failed (ADR-012).
    if (check.applies && !check.applies(ctx)) {
      notApplicable.push(check.meta.id);
      const why = check.notApplicableReason ?? 'they do not apply to this kind of app';
      notApplicableWhy.set(why, (notApplicableWhy.get(why) ?? 0) + 1);
      continue;
    }
    let outcome;
    try {
      outcome = check.run(ctx);
    } catch (err) {
      outcome = { passed: false, summary: `The check could not run: ${err instanceof Error ? err.message : String(err)}` };
    }
    evidence.push(
      buildEvidence({
        type: 'config',
        tier: 'medium',
        ref: check.meta.id,
        summary: outcome.summary,
        passed: outcome.passed,
        tool: CONFIG_TOOL.name,
        toolVersion: CONFIG_TOOL.version,
        runId: ctx.runId,
        capturedAt: new Date().toISOString(),
        location: outcome.file ? { file: outcome.file, line: outcome.line } : undefined,
        producedBy: 'rules',
        // What this check verifies, so the compliance evaluation can credit those requirements directly.
        requirementIds: [...check.meta.asvs, ...check.meta.aisvs],
      }),
    );
    if (!outcome.passed) {
      findings.push(
        buildFinding(ctx, {
          source: 'config',
          rule: outcome.severity ? { ...check.meta, severity: outcome.severity } : check.meta,
          file: outcome.file,
          line: outcome.line,
          evidence: outcome.summary,
          tool: CONFIG_TOOL,
        }),
      );
    }
  }

  if (ctx.abort.aborted) {
    return {
      findings,
      evidence: [],
      coverage: { tool: CONFIG_TOOL.name, ran: false, version: CONFIG_TOOL.version, reason: 'The run was cancelled before the configuration check finished.' },
      status: 'skipped',
      summary: 'Configuration checks were cancelled before they finished.',
    };
  }

  const status = statusFromFindings(findings);
  const passedCount = evidence.filter((e) => e.passed).length;
  const ranCount = ALL_CONFIG_CHECKS.length - notApplicable.length;
  const notApplicableText =
    notApplicable.length === 0
      ? ''
      : ` ${notApplicable.length} check${notApplicable.length === 1 ? '' : 's'} did not apply to this app and ${notApplicable.length === 1 ? 'was' : 'were'} not counted either way: ${[...notApplicableWhy.entries()].map(([why, n]) => `${n} because ${why}`).join('; ')}.`;
  const summary =
    findings.length === 0
      ? `All ${ranCount} configuration and documentation checks passed.${notApplicableText}`
      : `${passedCount} of ${ranCount} configuration and documentation checks passed; ${findings.length} did not (${countBySeverityText(findings)}).${notApplicableText}`;
  ctx.log(summary);

  const result: ScanResult = {
    findings,
    evidence,
    coverage: {
      tool: CONFIG_TOOL.name,
      ran: true,
      version: CONFIG_TOOL.version,
      covers: `${CONFIG_CHECKS.length} checks: environment files, secret strength, TLS/proxy settings, session policy, protected-file integrity, and required documentation.`,
    },
    details: { checks: CONFIG_CHECKS.length, passed: passedCount, failed: findings.length, notApplicable },
    status,
    summary,
  };
  return result;
};
