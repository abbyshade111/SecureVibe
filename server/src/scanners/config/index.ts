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

export const CONFIG_TOOL = { name: 'securevibe-config', version: '1.0.0' };

export const runConfig: Scanner = async (ctx) => {
  ctx.log('Checking configuration: environment files, secrets, TLS settings, protected files…');
  const findings: Finding[] = [];
  const evidence: Evidence[] = [];

  for (const check of CONFIG_CHECKS) {
    if (ctx.abort.aborted) break;
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
  const summary =
    findings.length === 0
      ? `All ${CONFIG_CHECKS.length} configuration checks passed.`
      : `${passedCount} of ${CONFIG_CHECKS.length} configuration checks passed; ${findings.length} did not (${countBySeverityText(findings)}).`;
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
    details: { checks: CONFIG_CHECKS.length, passed: passedCount, failed: findings.length },
    status,
    summary,
  };
  return result;
};
