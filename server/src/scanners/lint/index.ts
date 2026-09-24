/**
 * The lint scanner (CONTRACTS §3): runs eslint-plugin-security's recommended rules (with
 * the noisy rules listed in NOISY_RULES off) over the app's runtime code using SecureVibe's own ESLint/typescript-eslint install,
 * and turns each message into a Finding (source 'lint', ruleId 'lint.<eslint rule>').
 */
import { isAbsolute, relative, sep } from 'node:path';
import { ESLint, type Linter } from 'eslint';
import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';
import type { Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import { buildEvidence, buildFinding, countBySeverityText, lineTextAt, statusFromFindings } from '../sast/findings.js';
import { originFor } from '../sast/files.js';
import type { ScanContext, ScanResult, Scanner } from '../types.js';
import { LINT_RULE_META } from './severity.js';

export const LINT_TOOL = { name: 'eslint', version: ESLint.version };

/** eslint-plugin-security has no published types (see eslint-plugin-security.d.ts); cast once at the boundary. */
const securityPlugin = security as unknown as { configs: { recommended: { rules: Linter.RulesRecord } } } & ESLint.Plugin;

/**
 * Rules left out because they flag every occurrence of a pattern rather than the dangerous ones, which buried real
 * findings under hundreds of false alarms. The static analyser covers each of them precisely instead:
 * object indexing (sast.proto-pollution-merge), file paths from user input (sast.fs-user-path,
 * sast.path-join-user-input) and regular expressions built from user input (sast.regex-from-user-input).
 */
const NOISY_RULES = new Set(['security/detect-object-injection', 'security/detect-non-literal-fs-filename', 'security/detect-non-literal-regexp']);

const SECURITY_RULES = Object.fromEntries(
  Object.entries(securityPlugin.configs.recommended.rules).filter(([id]) => !NOISY_RULES.has(id)),
) as Linter.RulesRecord;

/**
 * Extra patterns (beyond `ctx.ignore` and the default ignore list) that never make sense to lint. Test suites and
 * build scripts do not run inside the deployed app, so they are not part of its attack surface.
 */
const EXTRA_IGNORES = ['node_modules/**', 'data/**', 'dist/**', 'coverage/**', 'certs/**', '**/*.min.js', '**/tests/**', '**/*.test.*', 'scripts/**'];

function baseConfig(ctx: ScanContext): Linter.Config[] {
  return [
    { ignores: [...EXTRA_IGNORES, ...ctx.ignore.map((p) => (p.includes('*') || p.includes('/') ? p : `**/${p}/**`))] },
    {
      files: ['**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts', '**/*.js', '**/*.jsx', '**/*.mjs', '**/*.cjs'],
      languageOptions: {
        parser: tseslint.parser,
        ecmaVersion: 'latest' as const,
        sourceType: 'module' as const,
      },
      plugins: { security: securityPlugin },
      rules: SECURITY_RULES,
    },
  ];
}

export const runLint: Scanner = async (ctx) => {
  ctx.log('Checking coding rules: running the security linter…');
  const eslint = new ESLint({
    cwd: ctx.appDir,
    overrideConfigFile: true,
    baseConfig: baseConfig(ctx),
    errorOnUnmatchedPattern: false,
  });

  let results: ESLint.LintResult[];
  try {
    results = await eslint.lintFiles(['**/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs}']);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      findings: [],
      evidence: [],
      coverage: { tool: LINT_TOOL.name, ran: false, version: LINT_TOOL.version, reason: `ESLint could not run: ${message}` },
      status: 'skipped',
      summary: `The security linter could not run: ${message}`,
    };
  }

  const findings: Finding[] = [];
  let filesLinted = 0;
  for (const result of results) {
    if (ctx.abort.aborted) break;
    filesLinted += 1;
    const relPath = isAbsolute(result.filePath) ? relative(ctx.appDir, result.filePath).split(sep).join('/') : result.filePath;
    const text = result.source;
    for (const message of result.messages) {
      if (!message.ruleId || !message.ruleId.startsWith('security/')) continue; // parse errors and non-security rules are out of scope here
      const short = message.ruleId.slice('security/'.length);
      const rule = LINT_RULE_META[short];
      if (!rule) continue;
      const line = message.line ?? 1;
      const snippet = text ? lineTextAt(text, line) : (message.message ?? '');
      findings.push(
        buildFinding(ctx, {
          source: 'lint',
          rule,
          file: relPath,
          line,
          column: message.column,
          endLine: message.endLine,
          snippet,
          evidence: `${message.ruleId}: ${message.message} (${relPath}:${line})`,
          introducedBy: originFor(ctx, relPath, text),
          tool: LINT_TOOL,
        }),
      );
    }
  }

  if (ctx.abort.aborted) {
    return {
      findings,
      evidence: [],
      coverage: { tool: LINT_TOOL.name, ran: false, version: LINT_TOOL.version, reason: 'The run was canceled before linting finished.' },
      status: 'skipped',
      summary: 'Linting was canceled before it finished.',
    };
  }

  const evidence: Evidence[] = [
    buildEvidence({
      type: 'scanner',
      tier: 'medium',
      ref: 'lint:eslint-plugin-security',
      summary: findings.length === 0 ? `eslint-plugin-security found no issues in ${filesLinted} files.` : `eslint-plugin-security found ${findings.length} issue${findings.length === 1 ? '' : 's'}.`,
      passed: findings.length === 0,
      tool: LINT_TOOL.name,
      toolVersion: LINT_TOOL.version,
      runId: ctx.runId,
      capturedAt: new Date().toISOString(),
      producedBy: 'rules',
    }),
  ];

  const status = statusFromFindings(findings);
  const summary =
    findings.length === 0
      ? `The security linter checked ${filesLinted} files and found no issues.`
      : `The security linter checked ${filesLinted} files and found ${findings.length} issue${findings.length === 1 ? '' : 's'} (${countBySeverityText(findings)}).`;
  ctx.log(summary);

  const result: ScanResult = {
    findings,
    evidence,
    coverage: {
      tool: LINT_TOOL.name,
      ran: true,
      version: LINT_TOOL.version,
      covers: 'eslint-plugin-security recommended rules (except three that flag nearly every line of typed code: object-injection, non-literal fs filename, non-literal regexp): unsafe regex, weak randomness, command execution, non-literal require, timing-unsafe comparisons and more. Test files and build scripts are not linted.',
    },
    details: { filesLinted, byRule: byRuleCounts(findings) },
    status,
    summary,
  };
  return result;
};

function byRuleCounts(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.ruleId] = (out[f.ruleId] ?? 0) + 1;
  return out;
}
