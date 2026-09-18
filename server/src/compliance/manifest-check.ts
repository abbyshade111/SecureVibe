/**
 * Re-verifies every template control of securevibe.manifest.json on the generated code (DESIGN §6, CONTRACTS §1.15).
 *
 * A control is credited only when ALL its checks pass AND at least one passing check is a test, a runtime probe, a
 * named AST check, a config-value check or a doc-generated check. `file-exists`, `file-contains`, `file-not-contains`
 * and `sast-clean` are supporting checks: they can fail a control but never carry it on their own.
 */
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, normalize, relative } from 'node:path';
import type { Evidence, EvidenceType } from '@shared/compliance.js';
import { EVIDENCE_TIER } from '@shared/compliance.js';
import type { BuildSpec } from '@shared/design.js';
import { isOpen } from '@shared/findings.js';
import type { ManifestCheck, TemplateControl, TemplateManifest } from '@shared/knowledge.js';
import { EvidenceIds } from './evidence-ids.js';
import type { ManifestCheckContext, ManifestCheckOutcome, ManifestControlResult } from './types.js';

/** Check types that may carry the credit for a control (shared/src/knowledge.ts). */
export const CREDITING_CHECK_TYPES: ReadonlySet<ManifestCheck['type']> = new Set(['test', 'dast', 'ast', 'config-value', 'doc-generated']);

/** Manifest feature ids (CONTRACTS §1.15) → BuildSpec feature flags. Ids not listed here come from `extraFeatures`. */
const FEATURE_FLAGS: Record<string, keyof BuildSpec['features']> = {
  auth: 'auth',
  'admin-mfa': 'adminMfa',
  'user-mfa': 'userMfa',
  uploads: 'uploads',
  ai: 'ai',
  'ai-actions': 'aiActions',
  'ai-moderation': 'aiModeration',
  email: 'email',
  scheduler: 'scheduler',
  'public-api': 'publicApi',
  payments: 'payments',
  'field-encryption': 'fieldEncryption',
  retention: 'retentionJobs',
};

/** "external-apis|ai|email" means any of them. */
export function featureEnabled(requires: string, buildSpec: BuildSpec, extra: Record<string, boolean> = {}): boolean {
  return requires
    .split('|')
    .map((id) => id.trim())
    .filter(Boolean)
    .some((id) => {
      const flag = FEATURE_FLAGS[id];
      if (flag) return buildSpec.features[flag];
      return extra[id] === true;
    });
}

export function controlExpected(
  control: TemplateControl,
  buildSpec: BuildSpec,
  extra: Record<string, boolean> = {},
): { expected: boolean; reason?: string } {
  if (control.requiresFeature && !featureEnabled(control.requiresFeature, buildSpec, extra)) {
    return { expected: false, reason: `Not expected: the "${control.requiresFeature}" feature is switched off in this app.` };
  }
  if (control.tlsModes && !control.tlsModes.includes(buildSpec.features.tlsMode)) {
    return {
      expected: false,
      reason: `Not expected: this control only applies when the app runs with TLS mode ${control.tlsModes.join(' or ')} (this app uses "${buildSpec.features.tlsMode}").`,
    };
  }
  return { expected: true };
}

function describeCheck(check: ManifestCheck): string {
  switch (check.type) {
    case 'file-exists':
      return `file ${check.file} exists`;
    case 'file-contains':
      return `file ${check.file} contains /${check.pattern}/`;
    case 'file-not-contains':
      return `file ${check.file} does not contain /${check.pattern}/`;
    case 'ast':
      return `code check "${check.check}"${check.file ? ` on ${check.file}` : ''}`;
    case 'test':
      return `test "${check.name}"`;
    case 'dast':
      return `runtime probe ${check.probe}`;
    case 'config-value':
      return `config check ${check.key}`;
    case 'sast-clean':
      return `no open findings for ${check.rules.join(', ')}`;
    case 'doc-generated':
      return `generated document ${check.file} matches its source of truth`;
  }
}

/** Resolves a manifest-relative file inside appDir; paths that escape the app folder are rejected. */
function confinedPath(appDir: string, file: string): string | undefined {
  if (isAbsolute(file) || file.includes('\0')) return undefined;
  const full = normalize(join(appDir, file));
  const rel = relative(appDir, full);
  if (rel.startsWith('..') || isAbsolute(rel)) return undefined;
  return full;
}

function readAppFile(appDir: string, file: string): { content?: string; problem?: string } {
  const full = confinedPath(appDir, file);
  if (!full) return { problem: `path ${file} is outside the app folder` };
  if (!existsSync(full)) return { problem: `file ${file} is missing` };
  try {
    return { content: readFileSync(full, 'utf8') };
  } catch (err) {
    return { problem: `file ${file} could not be read: ${(err as Error).message}` };
  }
}

function regexFor(pattern: string, flags: string | undefined): RegExp | undefined {
  try {
    return new RegExp(pattern, flags ?? '');
  } catch {
    return undefined;
  }
}

async function runCheck(check: ManifestCheck, ctx: ManifestCheckContext): Promise<ManifestCheckOutcome> {
  const skipped = (reason: string): ManifestCheckOutcome => ({ check, passed: false, detail: `Not checked: ${reason}`, skippedReason: reason });
  try {
    switch (check.type) {
      case 'file-exists': {
        const full = confinedPath(ctx.appDir, check.file);
        const ok = full !== undefined && existsSync(full);
        return { check, passed: ok, detail: ok ? `${check.file} is present` : `${check.file} is missing` };
      }
      case 'file-contains':
      case 'file-not-contains': {
        const { content, problem } = readAppFile(ctx.appDir, check.file);
        if (content === undefined) return { check, passed: false, detail: problem ?? 'unreadable' };
        const re = regexFor(check.pattern, check.flags);
        if (!re) return { check, passed: false, detail: `invalid pattern /${check.pattern}/ in the manifest`, errored: true };
        const found = re.test(content);
        if (check.type === 'file-contains') {
          return { check, passed: found, detail: found ? `${check.file} still contains the expected code` : `${check.file} no longer contains /${check.pattern}/ — the control may have been removed` };
        }
        return { check, passed: !found, detail: found ? `${check.file} contains forbidden pattern /${check.pattern}/` : `${check.file} is free of /${check.pattern}/` };
      }
      case 'ast': {
        if (ctx.skipped?.sast) return skipped(ctx.skipped.sast);
        const result = await ctx.astCheck(check.check, check.file);
        if (result.skippedReason) return skipped(result.skippedReason);
        return { check, passed: result.passed, detail: result.detail };
      }
      case 'test': {
        if (ctx.skipped?.tests) return skipped(ctx.skipped.tests);
        const matches = ctx.testResults.filter((t) => t.name.includes(check.name));
        if (matches.length === 0) {
          if (ctx.testResults.length === 0) return skipped('the test suite did not run or produced no results');
          return { check, passed: false, detail: `no test named "${check.name}" was found — it may have been removed` };
        }
        const ran = matches.filter((t) => !t.skipped);
        if (ran.length === 0) return skipped(`test "${check.name}" was skipped`);
        const failed = ran.filter((t) => !t.ok);
        return failed.length === 0
          ? { check, passed: true, detail: `${ran.length} test(s) named "${check.name}" passed` }
          : { check, passed: false, detail: `test failed: ${failed.map((t) => t.name).join('; ')}` };
      }
      case 'dast': {
        if (ctx.skipped?.dast) return skipped(ctx.skipped.dast);
        const probe = ctx.probeResults.find((p) => p.id === check.probe);
        if (!probe) {
          if (ctx.probeResults.length === 0) return skipped('the runtime scan did not run');
          return { check, passed: false, detail: `runtime probe ${check.probe} was not run` };
        }
        if (probe.passed === null) return skipped(probe.reason ?? `probe ${check.probe} could not run`);
        return {
          check,
          passed: probe.passed,
          detail: probe.passed
            ? `probe ${check.probe} passed${probe.observed ? `: ${probe.observed}` : ''}`
            : `probe ${check.probe} failed${probe.expected ? ` (expected ${probe.expected}` : ''}${probe.observed ? `${probe.expected ? '; ' : ' ('}observed ${probe.observed})` : probe.expected ? ')' : ''}`,
        };
      }
      case 'config-value': {
        if (ctx.skipped?.config) return skipped(ctx.skipped.config);
        const result = ctx.configResults.find((c) => c.id === check.key);
        if (!result) {
          if (ctx.configResults.length === 0) return skipped('the configuration checks did not run');
          return { check, passed: false, detail: `no result for config check ${check.key}` };
        }
        if (result.passed === null) return skipped(result.detail || `config check ${check.key} could not run`);
        return { check, passed: result.passed, detail: result.detail };
      }
      case 'sast-clean': {
        if (ctx.skipped?.sast) return skipped(ctx.skipped.sast);
        const rules = new Set(check.rules);
        const open = ctx.sastFindings.filter((f) => rules.has(f.ruleId) && isOpen(f));
        return open.length === 0
          ? { check, passed: true, detail: `no open findings from ${check.rules.length} rule(s): ${check.rules.join(', ')}` }
          : { check, passed: false, detail: `${open.length} open finding(s): ${open.map((f) => `${f.id} (${f.ruleId})`).join(', ')}` };
      }
      case 'doc-generated': {
        if (ctx.skipped?.docs) return skipped(ctx.skipped.docs);
        const result = await ctx.docsRegenerate(check.file);
        return {
          check,
          passed: result.matches,
          detail: result.detail ?? (result.matches ? `${check.file} matches a fresh regeneration from its source of truth` : `${check.file} differs from its source of truth (edited by hand or stale)`),
        };
      }
    }
  } catch (err) {
    return { check, passed: false, detail: `check could not run: ${(err as Error).message}`, errored: true };
  }
}

const EVIDENCE_TYPE_BY_CHECK: Record<ManifestCheck['type'], EvidenceType> = {
  test: 'test',
  dast: 'dast',
  ast: 'scanner',
  'sast-clean': 'scanner',
  'config-value': 'config',
  'doc-generated': 'design',
  'file-exists': 'template-control',
  'file-contains': 'template-control',
  'file-not-contains': 'template-control',
};

function checkRef(check: ManifestCheck): string {
  switch (check.type) {
    case 'test':
      return `test:${check.name}`;
    case 'dast':
      return `dast:${check.probe}`;
    case 'ast':
      return `ast:${check.check}`;
    case 'config-value':
      return `config:${check.key}`;
    case 'sast-clean':
      return `sast-clean:${check.rules.join(',')}`;
    case 'doc-generated':
      return `doc:${check.file}`;
    case 'file-exists':
      return `file-exists:${check.file}`;
    case 'file-contains':
    case 'file-not-contains':
      return `${check.type}:${check.file}`;
  }
}

function toolFor(check: ManifestCheck): string {
  switch (check.type) {
    case 'test':
      return 'node:test';
    case 'dast':
      return 'securevibe-dast';
    case 'ast':
    case 'sast-clean':
      return 'securevibe-sast';
    case 'config-value':
      return 'securevibe-config';
    case 'doc-generated':
      return 'docs:build';
    default:
      return 'securevibe-manifest';
  }
}

export async function evaluateManifestControls(manifest: TemplateManifest, ctx: ManifestCheckContext): Promise<ManifestControlResult[]> {
  const ids = new EvidenceIds('EM');
  const results: ManifestControlResult[] = [];
  const capturedAt = ctx.capturedAt ?? new Date().toISOString();

  for (const control of manifest.controls) {
    const { expected, reason } = controlExpected(control, ctx.buildSpec, ctx.extraFeatures);
    if (!expected) {
      results.push({ controlId: control.id, expected: false, notExpectedReason: reason, checks: [], passed: false, creditedBy: [], docOnly: false, errored: false, evidence: [] });
      continue;
    }

    const checks: ManifestCheckOutcome[] = [];
    for (const check of control.checks) checks.push(await runCheck(check, ctx));

    const allPassed = checks.every((c) => c.passed);
    const creditedBy = [...new Set(checks.filter((c) => c.passed && CREDITING_CHECK_TYPES.has(c.check.type)).map((c) => c.check.type))];
    const passed = allPassed && creditedBy.length > 0;
    const docOnly = passed && creditedBy.every((t) => t === 'doc-generated');
    const skippedReason = checks.find((c) => c.skippedReason)?.skippedReason;
    const errored = checks.some((c) => c.errored);

    const evidence: Evidence[] = checks
      .filter((c) => !c.skippedReason)
      .map((c) => {
        const type = EVIDENCE_TYPE_BY_CHECK[c.check.type];
        return {
          id: ids.next(),
          type,
          tier: EVIDENCE_TIER[type],
          ref: `${control.id}/${checkRef(c.check)}`,
          summary: `${control.title}: ${describeCheck(c.check)} — ${c.detail}`,
          passed: c.passed,
          tool: toolFor(c.check),
          ...(ctx.runId ? { runId: ctx.runId } : {}),
          capturedAt,
          producedBy: 'rules',
        };
      });

    results.push({ controlId: control.id, expected: true, checks, passed, creditedBy, docOnly, ...(skippedReason ? { skippedReason } : {}), errored, evidence });
  }
  return results;
}

/** One-line plain-language reason a control was not credited (for reports and rationales). */
export function controlFailureSummary(result: ManifestControlResult): string {
  if (!result.expected) return result.notExpectedReason ?? 'not expected in this build';
  if (result.passed) return 'credited';
  const failed = result.checks.filter((c) => !c.passed && !c.skippedReason);
  if (failed.length > 0) return failed.map((c) => `${describeCheck(c.check)}: ${c.detail}`).join('; ');
  if (result.skippedReason) return `not verified: ${result.skippedReason}`;
  return 'no test, probe, code check, config check or generated document could carry this control (file checks alone are not enough)';
}

export { describeCheck };
