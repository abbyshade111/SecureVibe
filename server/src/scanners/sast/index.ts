/**
 * The SAST scanner: lists the app's source files, parses TypeScript/JavaScript with the compiler API and
 * EJS with the tokenizer, runs every rule, and returns normalized findings plus "no issues" evidence for
 * the rule ids the template manifest relies on (`sast-clean` checks).
 */
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { ScanContext, ScanResult, Scanner } from '../types.js';
import { isEjsPath, looksMinified, parseEjsFile, parseTsFile, runRulesOnFile, SAST_TOOL, scriptKindFor, type ScannedFile, type ScanTree, type SastRule } from './engine.js';
import { listAppFiles, originFor, readTextFile } from './files.js';
import { buildEvidence, buildFinding, countBySeverityText, lineTextAt, statusFromFindings } from './findings.js';
import { ALL_RULES } from './rules/index.js';

export { ALL_RULES, RULE_IDS, ruleById } from './rules/index.js';

/** Builds the parsed file tree once so the scanner and the AST checks share it. */
export function buildScanTree(ctx: ScanContext, options: { onlyPaths?: string[] } = {}): ScanTree {
  const listed = listAppFiles(ctx.appDir, ctx.ignore);
  const tree: ScanTree = { ctx, files: [], allPaths: listed.map((f) => f.relPath) };
  for (const entry of listed) {
    if (ctx.abort.aborted) break;
    if (options.onlyPaths && !options.onlyPaths.includes(entry.relPath)) continue;
    const kind = scriptKindFor(entry.relPath);
    const ejs = isEjsPath(entry.relPath);
    if (kind === undefined && !ejs) continue;
    const text = readTextFile(entry.absPath);
    if (text === undefined) continue;
    if (kind !== undefined) {
      if (looksMinified(entry.relPath, text)) continue;
      const parsed = parseTsFile(ctx, entry.relPath, entry.absPath, text);
      if (parsed) tree.files.push(parsed);
    } else {
      tree.files.push(parseEjsFile(ctx, entry.relPath, entry.absPath, text));
    }
  }
  return tree;
}

/** Runs `rules` over an already-built tree (used by runSast and by the named AST checks). */
export function runRulesOnTree(tree: ScanTree, rules: SastRule[]): Finding[] {
  const { ctx } = tree;
  const findings: Finding[] = [];
  for (const file of tree.files) {
    if (ctx.abort.aborted) break;
    findings.push(...runRulesOnFile(ctx, rules, file));
  }
  for (const rule of rules) {
    if (!rule.checkTree || ctx.abort.aborted) continue;
    rule.checkTree(tree, (relPath, opts) => {
      const scanned: ScannedFile | undefined = tree.files.find((f) => f.relPath === relPath);
      const snippet = opts.snippet ?? (scanned ? lineTextAt(scanned.text, opts.line) : '');
      findings.push(
        buildFinding(ctx, {
          source: 'sast',
          rule,
          file: relPath,
          line: opts.line,
          column: opts.column,
          snippet,
          evidence: opts.evidence ?? `${relPath}:${opts.line}: ${snippet}`,
          severity: opts.severity,
          confidence: opts.confidence,
          introducedBy: scanned?.origin ?? originFor(ctx, relPath),
          tool: SAST_TOOL,
          fingerprintExtra: opts.fingerprintExtra,
        }),
      );
    });
  }
  return findings;
}

/** Rule ids the manifest cites in `sast-clean` checks; each gets a pass/fail evidence row. */
function manifestSastCleanRules(ctx: ScanContext): string[] {
  const ids = new Set<string>();
  for (const control of ctx.manifest?.controls ?? []) {
    for (const check of control.checks) if (check.type === 'sast-clean') for (const id of check.rules) ids.add(id);
  }
  return [...ids];
}

export const runSast: Scanner = async (ctx) => {
  ctx.log(`Static analysis: reading source files under ${ctx.appDir}`);
  const tree = buildScanTree(ctx);
  const tsCount = tree.files.filter((f) => f.kind === 'ts').length;
  const ejsCount = tree.files.filter((f) => f.kind === 'ejs').length;
  const findings = runRulesOnTree(tree, ALL_RULES);

  if (ctx.abort.aborted) {
    return {
      findings,
      evidence: [],
      coverage: { tool: SAST_TOOL.name, ran: false, version: SAST_TOOL.version, reason: 'The run was cancelled before static analysis finished.' },
      status: 'skipped',
      summary: 'Static analysis was cancelled before it finished.',
    };
  }

  const byRule = new Map<string, number>();
  for (const f of findings) byRule.set(f.ruleId, (byRule.get(f.ruleId) ?? 0) + 1);

  const evidence: Evidence[] = manifestSastCleanRules(ctx).map((ruleId) => {
    const rule = ALL_RULES.find((r) => r.id === ruleId);
    const count = byRule.get(ruleId) ?? 0;
    return buildEvidence({
      type: 'scanner',
      tier: 'medium',
      ref: `sast:${ruleId}`,
      summary:
        count === 0
          ? `No "${rule?.title ?? ruleId}" issues were found in ${tsCount + ejsCount} source files.`
          : `${count} "${rule?.title ?? ruleId}" issue${count === 1 ? '' : 's'} found.`,
      passed: count === 0,
      tool: SAST_TOOL.name,
      toolVersion: SAST_TOOL.version,
      runId: ctx.runId,
      capturedAt: new Date().toISOString(),
      producedBy: 'rules',
    });
  });

  const status = statusFromFindings(findings);
  const counts = countBySeverityText(findings);
  const summary =
    findings.length === 0
      ? `Static analysis read ${tsCount} code files and ${ejsCount} page templates with ${ALL_RULES.length} rules and found no issues.`
      : `Static analysis read ${tsCount} code files and ${ejsCount} page templates with ${ALL_RULES.length} rules and found ${findings.length} issue${findings.length === 1 ? '' : 's'} (${counts}).`;
  ctx.log(summary);

  return {
    findings,
    evidence,
    coverage: {
      tool: SAST_TOOL.name,
      ran: true,
      version: SAST_TOOL.version,
      covers: `${ALL_RULES.length} rules for injection, unsafe APIs, weak cryptography, cookies and headers, route registration, validation, templates and AI guard-rails over TypeScript, JavaScript and EJS files.`,
    },
    details: {
      filesScanned: tree.files.length,
      typescriptFiles: tsCount,
      templateFiles: ejsCount,
      rulesRun: ALL_RULES.length,
      byRule: Object.fromEntries(byRule),
    },
    status,
    summary,
  };
};
