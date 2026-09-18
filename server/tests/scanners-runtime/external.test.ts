/**
 * The optional external scanners. Two things must hold: their output maps into ordinary findings, and a tool that
 * is not installed produces an honest "skipped: not installed" coverage row rather than silence.
 *
 * A fake tool on PATH stands in for the real ones so the test runs the same way on every machine.
 */
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  detectTool,
  externalCoverageRows,
  findOnPath,
  parseGitleaks,
  parseOsvScanner,
  parseSemgrep,
  parseTrivy,
  parseVersion,
  runExternal,
  toFinding,
  toolCacheEnv,
  type ExternalDetails,
} from '../../src/scanners/external/index.js';
import type { ScanContext } from '../../src/scanners/types.js';
import { buildSpecFor } from './helpers/mini-app.js';

const FIXTURES = fileURLToPath(new URL('../fixtures/scanners-runtime/external/', import.meta.url));
const APP_DIR = '/absolute/app';

function fixture(name: string): string {
  return readFileSync(join(FIXTURES, name), 'utf8');
}

let projectDir: string;
let binDir: string;
let originalPath: string | undefined;

beforeEach(() => {
  projectDir = mkdtempSync(join(tmpdir(), 'securevibe-external-'));
  binDir = mkdtempSync(join(tmpdir(), 'securevibe-bin-'));
  originalPath = process.env['PATH'];
});

afterEach(() => {
  if (originalPath === undefined) delete process.env['PATH'];
  else process.env['PATH'] = originalPath;
  rmSync(projectDir, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
});

function contextFor(appDir = projectDir): ScanContext {
  return {
    appDir,
    projectDir,
    runId: 'run-external-1',
    buildSpec: buildSpecFor(),
    manifest: undefined as never,
    ignore: [],
    toolCacheDir: join(tmpdir(), 'securevibe-tool-cache-test'),
    knowledge: undefined as never,
    log: () => {},
    abort: new AbortController().signal,
  };
}

/** Puts a shell-free fake tool on PATH that prints a fixture when asked to scan. */
function fakeTool(name: string, versionOutput: string, scanOutput: string): void {
  const file = join(binDir, name);
  const script = `#!${process.execPath}
const args = process.argv.slice(2);
if (args.includes('--version')) { process.stdout.write(${JSON.stringify(versionOutput)}); process.exit(0); }
const reportIndex = args.indexOf('--report-path');
if (reportIndex >= 0) { require('node:fs').writeFileSync(args[reportIndex + 1], ${JSON.stringify(scanOutput)}); process.exit(1); }
process.stdout.write(${JSON.stringify(scanOutput)});
process.exit(0);
`;
  writeFileSync(file, script);
  chmodSync(file, 0o755);
  process.env['PATH'] = `${binDir}:${originalPath ?? ''}`;
}

describe('finding a tool on PATH', () => {
  it('finds a tool that is there and not one that is not', async () => {
    fakeTool('semgrep', 'semgrep 1.90.0\n', fixture('semgrep.json'));
    expect(findOnPath('semgrep')).toBe(join(binDir, 'semgrep'));
    expect(findOnPath('definitely-not-installed-xyz')).toBeUndefined();
    const detected = await detectTool('semgrep', projectDir);
    expect(detected?.version).toBe('1.90.0');
  }, 60_000);

  it('reads a version number out of the usual shapes', () => {
    expect(parseVersion('semgrep 1.90.0')).toBe('1.90.0');
    expect(parseVersion('v8.18.2')).toBe('8.18.2');
    expect(parseVersion('Version: 0.49.0\n')).toBe('0.49.0');
    expect(parseVersion('no numbers here')).toBeUndefined();
  });
});

describe('mapping tool output to findings', () => {
  it('maps semgrep results, including the CWE and the file path', () => {
    const seeds = parseSemgrep(fixture('semgrep.json'), APP_DIR);
    expect(seeds).toHaveLength(2);
    expect(seeds[0]?.file).toBe('src/features/notes/index.ts');
    expect(seeds[0]?.line).toBe(42);
    expect(seeds[0]?.severity).toBe('medium');
    expect(seeds[0]?.cwe).toEqual(['CWE-1004']);
    // Absolute paths are made relative to the app folder.
    expect(seeds[1]?.file).toBe('src/db/reports.ts');
    expect(seeds[1]?.severity).toBe('high');
  });

  it('maps gitleaks results without copying the secret into the report', () => {
    const seeds = parseGitleaks(fixture('gitleaks.json'), APP_DIR);
    expect(seeds).toHaveLength(1);
    expect(seeds[0]?.severity).toBe('high');
    expect(seeds[0]?.file).toBe('src/features/ai/prompt.ts');
    expect(seeds[0]?.snippet).toBeUndefined();
    expect(seeds[0]?.evidence).not.toContain('REDACTED');
    expect(seeds[0]?.cwe).toEqual(['CWE-798']);
  });

  it('maps trivy vulnerabilities, secrets and configuration problems', () => {
    const seeds = parseTrivy(fixture('trivy.json'), APP_DIR);
    expect(seeds).toHaveLength(3);
    const vuln = seeds.find((s) => s.ruleId === 'CVE-2024-11111')!;
    expect(vuln.severity).toBe('high');
    expect(vuln.dependency?.package).toBe('left-pad');
    expect(vuln.dependency?.fixedVersion).toBe('1.3.1');
    expect(seeds.find((s) => s.ruleId === 'generic-api-key')?.severity).toBe('critical');
    expect(seeds.find((s) => s.ruleId === 'DS002')?.severity).toBe('medium');
  });

  it('maps osv-scanner results with their aliases', () => {
    const seeds = parseOsvScanner(fixture('osv-scanner.json'), APP_DIR);
    expect(seeds).toHaveLength(1);
    expect(seeds[0]?.ruleId).toBe('GHSA-abcd-1234-efgh');
    expect(seeds[0]?.severity).toBe('high');
    expect(seeds[0]?.dependency?.advisoryIds).toEqual(['GHSA-abcd-1234-efgh', 'CVE-2024-11111']);
    expect(seeds[0]?.file).toBe('package-lock.json');
  });

  it('ignores output it cannot read instead of throwing', () => {
    for (const parse of [parseSemgrep, parseGitleaks, parseTrivy, parseOsvScanner]) {
      expect(parse('not json at all', APP_DIR)).toEqual([]);
    }
  });

  it('builds a finding that says where it came from and what to do', () => {
    const [seed] = parseSemgrep(fixture('semgrep.json'), APP_DIR);
    const finding = toFinding(seed!, '1.90.0');
    expect(finding.source).toBe('external');
    expect(finding.ruleId).toBe('external.semgrep.javascript.express.security.audit.express-cookie-session-no-httponly');
    expect(finding.tool).toEqual({ name: 'semgrep', version: '1.90.0' });
    expect(finding.confidence).toBe('medium');
    expect(finding.impact).toContain('semgrep');
    expect(finding.remediation.steps.length).toBeGreaterThan(0);
    expect(finding.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('runExternal', () => {
  it('records "skipped: not installed" for every tool that is not there', async () => {
    process.env['PATH'] = binDir; // an empty folder: nothing is installed
    const result = await runExternal(contextFor());
    const details = result.details as ExternalDetails;
    expect(result.status).toBe('skipped');
    expect(result.findings).toEqual([]);
    expect(details.tools.map((t) => t.name)).toEqual(['semgrep', 'gitleaks', 'trivy', 'osv-scanner', 'nano-analyzer']);
    const onPath = details.tools.filter((t) => t.name !== 'nano-analyzer');
    expect(onPath.every((t) => !t.installed && t.reason === 'skipped: not installed')).toBe(true);
    // The opt-in AI scanner is skipped for a different reason: it was never switched on, which is not the same
    // thing as missing, and the coverage table has to say which of the two it was.
    expect(details.tools.at(-1)).toMatchObject({ name: 'nano-analyzer', ran: false, findingCount: 0 });
    expect(details.tools.at(-1)!.reason).toMatch(/not switched on in Settings/);
    expect(externalCoverageRows(result)).toHaveLength(5);
    expect(externalCoverageRows(result).every((row) => row.ran === false && row.covers)).toBe(true);
    expect(result.coverage.reason).toMatch(/not installed/);
    expect(result.summary).toMatch(/No extra security scanners are installed/);
  }, 60_000);

  it('gives the scanners one cache folder for the whole workspace, not one per project', async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'sv-tool-cache-'));
    const env = toolCacheEnv(cacheDir);
    // trivy's database is over a gigabyte; without this it is downloaded again into every project's own HOME.
    expect(env['TRIVY_CACHE_DIR']).toBe(join(cacheDir, 'trivy'));
    expect(env['XDG_CACHE_HOME']).toBe(join(cacheDir, 'xdg'));
    expect(existsSync(cacheDir)).toBe(true);
    rmSync(cacheDir, { recursive: true, force: true });
  });

  it('runs a tool that is installed and maps what it reports', async () => {
    fakeTool('semgrep', 'semgrep 1.90.0\n', fixture('semgrep.json'));
    const result = await runExternal(contextFor(), { only: ['semgrep'] });
    const details = result.details as ExternalDetails;
    expect(details.tools[0]).toMatchObject({ name: 'semgrep', installed: true, ran: true, version: '1.90.0', findingCount: 2 });
    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.source === 'external')).toBe(true);
    expect(result.status).toBe('failed'); // one of the two is high severity
    expect(result.coverage.ran).toBe(true);
    expect(result.coverage.version).toContain('semgrep 1.90.0');
    expect(result.summary).toMatch(/Ran 1 extra scanner/);
  }, 60_000);

  it('reads a report file for tools that write one instead of printing it', async () => {
    fakeTool('gitleaks', 'v8.18.2\n', fixture('gitleaks.json'));
    const result = await runExternal(contextFor(), { only: ['gitleaks'] });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('external.gitleaks.generic-api-key');
    expect((result.details as ExternalDetails).tools[0]?.ran).toBe(true);
  }, 60_000);

  it('does not claim a tool ran when its output could not be read', async () => {
    fakeTool('trivy', 'Version: 0.49.0\n', 'this is not json');
    const result = await runExternal(contextFor(), { only: ['trivy'] });
    const tool = (result.details as ExternalDetails).tools[0]!;
    expect(tool.installed).toBe(true);
    expect(tool.findingCount).toBe(0);
    expect(result.findings).toEqual([]);
  }, 60_000);
});
