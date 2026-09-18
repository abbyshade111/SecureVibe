/**
 * Lint scanner (CONTRACTS §3): eslint-plugin-security's recommended rules run over the app dir with
 * `detect-object-injection` turned off, and findings map to `lint.<eslint rule>`.
 */
import { describe, expect, it } from 'vitest';
import { LINT_TOOL, runLint } from '../../src/scanners/lint/index.js';
import { fixtureDir, makeScanContext } from './helpers.js';

describe('lint scanner', () => {
  it('finds the expected eslint-plugin-security issues, and nothing for the disabled rule', async () => {
    const ctx = makeScanContext(fixtureDir('lint-app'));
    const result = await runLint(ctx);

    const byRuleAndLine = (ruleId: string, line: number): boolean => result.findings.some((f) => f.ruleId === ruleId && f.location?.file === 'src/risky.ts' && f.location?.line === line);

    expect(byRuleAndLine('lint.security/detect-child-process', 7)).toBe(true);
    expect(byRuleAndLine('lint.security/detect-pseudoRandomBytes', 11)).toBe(true);
    expect(byRuleAndLine('lint.security/detect-unsafe-regex', 14)).toBe(true);
    // detect-object-injection is switched off (CONTRACTS §3); the fixture's obj[key] must not appear.
    expect(result.findings.some((f) => f.ruleId === 'lint.security/detect-object-injection')).toBe(false);
    expect(result.status).toBe('failed');
  });

  it('every finding is source "lint" with the eslint tool name and version, and a stable fingerprint', async () => {
    const ctx = makeScanContext(fixtureDir('lint-app'));
    const result = await runLint(ctx);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(f.source).toBe('lint');
      expect(f.tool?.name).toBe(LINT_TOOL.name);
      expect(f.tool?.version).toBe(LINT_TOOL.version);
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(f.ruleId.startsWith('lint.security/')).toBe(true);
    }
  });

  it('reports a coverage row naming the eslint version', async () => {
    const ctx = makeScanContext(fixtureDir('lint-app'));
    const result = await runLint(ctx);
    expect(result.coverage.ran).toBe(true);
    expect(result.coverage.tool).toBe('eslint');
    expect(result.coverage.version).toBe(LINT_TOOL.version);
  });

  it('raises nothing on the clean fixture', async () => {
    const ctx = makeScanContext(fixtureDir('clean-app'));
    const result = await runLint(ctx);
    expect(result.findings).toEqual([]);
    expect(result.status).toBe('passed');
  });
});
