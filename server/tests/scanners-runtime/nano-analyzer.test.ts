/**
 * The optional AI scanner: it only ever runs when the owner asked for it, its suggestions are marked as
 * suggestions, and the key it needs never appears anywhere but the child process's environment.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  nanoArgs,
  nanoOptionsFor,
  parseNanoFinding,
  readNanoFindings,
  resolveNanoAnalyzer,
  runNanoAnalyzer,
  stageSources,
  type NanoAnalyzerOptions,
} from '../../src/scanners/external/nano-analyzer.js';
import { toFinding } from '../../src/scanners/external/parse.js';

const dirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const SETTINGS = { nanoAnalyzer: { enabled: true, scriptPath: '', model: 'gpt-5.4-nano', minConfidence: 0.7 } };

const FINDING = `# VULN-001: Session id compared with ==

- **File**: \`src/features/auth/session.ts\`
- **Confidence**: 80% [VVIV]
- **Project**: demo
- **Date**: 2026-09-18

---

## Scanner finding

[CRITICAL] F1 Session id compared with ==

The lookup compares the session id with a plain equality check, so the comparison is not constant time.
`;

describe('the optional AI scanner', () => {
  it('does not run unless it was switched on, given a folder and given a key', () => {
    const base: NanoAnalyzerOptions = { enabled: false, scriptPath: '/tmp/nano', model: 'gpt-5.4-nano', minConfidence: 0.7, apiKey: 'k' };
    expect(resolveNanoAnalyzer(base)).toMatchObject({ reason: expect.stringContaining('not switched on') });
    expect(resolveNanoAnalyzer({ ...base, enabled: true, scriptPath: '' })).toMatchObject({ reason: expect.stringContaining('no nano-analyzer folder') });
    const { apiKey: _omitted, ...withoutKey } = { ...base, enabled: true };
    expect(resolveNanoAnalyzer(withoutKey)).toMatchObject({ reason: expect.stringContaining('no OpenAI or OpenRouter key') });
    expect(resolveNanoAnalyzer({ ...base, enabled: true, scriptPath: 'nano' })).toMatchObject({ reason: expect.stringContaining('full path') });
    expect(resolveNanoAnalyzer({ ...base, enabled: true, scriptPath: join(tempDir('sv-nano-empty-')) })).toMatchObject({
      reason: expect.stringContaining('scan.py'),
    });
  });

  it('takes the key from the environment, and picks OpenRouter when the model name says so', () => {
    expect(nanoOptionsFor(SETTINGS, { OPENAI_API_KEY: 'sk-test' })).toMatchObject({ keyName: 'OPENAI_API_KEY', apiKey: 'sk-test' });
    expect(nanoOptionsFor(SETTINGS, {})).not.toHaveProperty('apiKey');
    const router = { nanoAnalyzer: { ...SETTINGS.nanoAnalyzer, model: 'anthropic/claude-sonnet-5' } };
    expect(nanoOptionsFor(router, { OPENROUTER_API_KEY: 'or-test', OPENAI_API_KEY: 'sk-test' })).toMatchObject({
      keyName: 'OPENROUTER_API_KEY',
      apiKey: 'or-test',
    });
  });

  it('runs the script against the app folder and writes its results outside it', () => {
    const scriptDir = tempDir('sv-nano-');
    writeFileSync(join(scriptDir, 'scan.py'), '# nano-analyzer\n');
    const opts: NanoAnalyzerOptions = { enabled: true, scriptPath: scriptDir, model: 'gpt-5.4-nano', minConfidence: 0.7, apiKey: 'k' };
    const resolved = resolveNanoAnalyzer(opts, '/usr/bin');
    if ('reason' in resolved) throw new Error(`Python 3 is expected on this computer: ${resolved.reason}`);
    const args = nanoArgs(resolved, opts, '/apps/demo', '/work/out');
    expect(args).toEqual([join(scriptDir, 'scan.py'), '/apps/demo', '--model', 'gpt-5.4-nano', '--output-dir', '/work/out', '--min-confidence', '0.7', '--repo-dir', '/apps/demo']);
  });

  it('reads a surviving finding, and leaves out the ones the tool was unsure about', () => {
    const out = tempDir('sv-nano-out-');
    mkdirSync(join(out, 'findings'));
    writeFileSync(join(out, 'findings', 'VULN-001_a.md'), FINDING);
    writeFileSync(join(out, 'findings', 'VULN-002_b.md'), FINDING.replace('80%', '40%').replace('VULN-001', 'VULN-002'));
    const seeds = readNanoFindings(out, 0.7);
    expect(seeds.map((s) => s.ruleId)).toEqual(['VULN-001']);
    expect(seeds[0]).toMatchObject({ tool: 'nano-analyzer', severity: 'critical', file: 'src/features/auth/session.ts' });
    expect(seeds[0]!.evidence).toContain('80% of those rounds');
  });

  it('records a suggestion as a suggestion: low confidence, never critical, never evidence', () => {
    const seed = parseNanoFinding(FINDING, 'VULN-001_a.md')!;
    const finding = toFinding(seed);
    expect(finding.confidence).toBe('low');
    // The tool called it critical; unproved opinions must not reach a level that stops a build.
    expect(finding.severityBase).toBe('critical');
    expect(finding.severity).toBe('medium');
    expect(finding.impact).toContain('did not run anything');
    expect(finding.remediation.steps.join(' ')).toContain('Decide whether it is real');
  });

  it('copies the app\'s own source out of reach of node_modules, and stops at the limit', () => {
    const appDir = tempDir('sv-nano-app-');
    mkdirSync(join(appDir, 'src'), { recursive: true });
    mkdirSync(join(appDir, 'node_modules', 'left-pad'), { recursive: true });
    writeFileSync(join(appDir, 'src', 'app.ts'), 'export const a = 1;\n');
    writeFileSync(join(appDir, 'src', 'notes.md'), '# not code\n');
    writeFileSync(join(appDir, 'node_modules', 'left-pad', 'index.js'), 'module.exports = 1;\n');
    const staged = stageSources(appDir, join(tempDir('sv-nano-stage-'), 'sources'));
    expect(staged.copied).toBe(1);
    expect(existsSync(join(staged.dir, 'src', 'app.ts'))).toBe(true);
    expect(existsSync(join(staged.dir, 'node_modules', 'left-pad', 'index.js'))).toBe(false);
    expect(existsSync(join(staged.dir, 'src', 'notes.md'))).toBe(false);
  });

  it('never passes the key anywhere but the child process, and says so when there is nothing to read', async () => {
    const scriptDir = tempDir('sv-nano-');
    writeFileSync(join(scriptDir, 'scan.py'), '# nano-analyzer\n');
    const workDir = tempDir('sv-nano-work-');
    mkdirSync(join(workDir, 'app', 'src'), { recursive: true });
    writeFileSync(join(workDir, 'app', 'src', 'app.ts'), 'export const a = 1;\n');
    const seen: { args: string[]; env: Record<string, string> }[] = [];
    const result = await runNanoAnalyzer(
      {
        appDir: join(workDir, 'app'),
        projectDir: workDir,
        runId: 'r_test',
        workDir,
        log: () => {},
        abort: new AbortController().signal,
        run: async (_file, args, env) => {
          seen.push({ args, env });
          return { code: 1, timedOut: false, stderr: 'nano-analyzer: no files to scan' };
        },
      },
      { enabled: true, scriptPath: scriptDir, model: 'gpt-5.4-nano', minConfidence: 0.7, apiKey: 'sk-secret-value' },
    );
    expect(result.ran).toBe(false);
    expect(result.reason).toContain('wrote no results');
    expect(result.reason).not.toContain('sk-secret-value');
    expect(seen[0]!.env).toEqual({ OPENAI_API_KEY: 'sk-secret-value' });
    expect(seen[0]!.args.join(' ')).not.toContain('sk-secret-value');
  });
});
