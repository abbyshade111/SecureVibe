import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PipelineRunSchema, type PipelineRun } from '@shared/pipeline.js';
import { FindingSchema, type Finding } from '@shared/findings.js';
import { buildScanData, scanDataFileName } from '../../src/reports/scan-data.js';

let home: string;
let reportsDir: string;
let runDir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sv-scan-data-'));
  reportsDir = join(home, 'reports', 'run-1');
  runDir = join(home, 'pipeline', 'run-1');
  mkdirSync(reportsDir, { recursive: true });
  mkdirSync(runDir, { recursive: true });
});
afterEach(() => rmSync(home, { recursive: true, force: true }));

function run(overrides: Partial<PipelineRun> = {}): PipelineRun {
  return PipelineRunSchema.parse({
    id: 'run-1',
    projectId: 'p-1',
    mode: 'full',
    startedAt: '2026-01-01T10:00:00.000Z',
    finishedAt: '2026-01-01T10:12:00.000Z',
    status: 'succeeded',
    stages: [
      { id: 'sast', status: 'warning', summary: 'Two risky patterns.', details: { rules: 41, matched: 2 }, round: 0 },
      { id: 'deps', status: 'passed', summary: 'No known problems.', details: { lockfile: { packageCount: 12 } }, round: 0 },
      { id: 'dast', status: 'skipped', summary: 'The packages did not install.', skippedReason: 'install failed', round: 0 },
    ],
    coverage: [
      { tool: 'semgrep', ran: false, reason: 'not installed on this computer', covers: 'Extra static analysis.' },
      { tool: 'npm audit', ran: true, version: 'npm 11.0.0', covers: 'Known problems in packages.' },
    ],
    ...overrides,
  });
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return FindingSchema.parse({
    id: 'F-0001',
    fingerprint: 'abc123',
    source: 'sast',
    ruleId: 'sv.sast.eval',
    title: 'Code is built from text at run time',
    severity: 'high',
    confidence: 'high',
    description: 'x',
    impact: 'y',
    evidence: 'z',
    remediation: { summary: 'Do not do that.' },
    location: { file: 'src/routes/admin.ts', line: 42 },
    ...overrides,
  });
}

function bundle(input: { run?: PipelineRun; findings?: Finding[] } = {}) {
  return buildScanData({
    project: { id: 'p-1', name: 'Bookings' },
    run: input.run ?? run(),
    findings: input.findings ?? [finding()],
    reportsDir,
    runDir,
    securevibeVersion: '0.1.0',
  });
}

const names = (b: ReturnType<typeof bundle>) => [...b.entries.map((e) => e.name), ...b.files.map((f) => f.name)].sort();

describe('the scan data pack', () => {
  it('carries the findings, the tool coverage and the run itself', () => {
    const b = bundle();
    expect(names(b)).toEqual(['README.txt', 'findings.json', 'run.json', 'scanners/dast.json', 'scanners/deps.json', 'scanners/sast.json', 'tool-coverage.json']);

    const findings = JSON.parse(b.entries.find((e) => e.name === 'findings.json')!.content) as { count: number; findings: Finding[] };
    expect(findings.count).toBe(1);
    expect(findings.findings[0]?.location).toEqual({ file: 'src/routes/admin.ts', line: 42 });

    const coverage = JSON.parse(b.entries.find((e) => e.name === 'tool-coverage.json')!.content) as { coverage: { tool: string; ran: boolean; reason?: string }[] };
    // A tool that did not run is listed with the reason, so the pack never implies coverage the build did not have.
    expect(coverage.coverage.find((c) => c.tool === 'semgrep')).toMatchObject({ ran: false, reason: 'not installed on this computer' });
  });

  it('keeps each scanner’s own output, including why a scanner was skipped', () => {
    const b = bundle();
    const sast = JSON.parse(b.entries.find((e) => e.name === 'scanners/sast.json')!.content) as { status: string; output: unknown };
    expect(sast.status).toBe('warning');
    expect(sast.output).toEqual({ rules: 41, matched: 2 });

    const dast = JSON.parse(b.entries.find((e) => e.name === 'scanners/dast.json')!.content) as { status: string; skippedReason: string; output: unknown };
    expect(dast.status).toBe('skipped');
    expect(dast.skippedReason).toBe('install failed');
    expect(dast.output).toBeNull();
  });

  it('includes the machine-readable report files and the raw probe results when they exist', () => {
    writeFileSync(join(reportsDir, 'findings.sarif'), '{}');
    writeFileSync(join(reportsDir, 'sbom.cdx.json'), '{}');
    writeFileSync(join(reportsDir, 'security-report.json'), '{}');
    // A report that was never written (this build produced no compliance result) is simply left out.
    mkdirSync(join(runDir, 'dast'), { recursive: true });
    writeFileSync(join(runDir, 'dast', 'probes.json'), '[]');

    const b = bundle();
    expect(names(b)).toContain('findings.sarif');
    expect(names(b)).toContain('sbom.cdx.json');
    expect(names(b)).toContain('security-report.json');
    expect(names(b)).toContain('dast/probes.json');
    expect(names(b)).not.toContain('compliance-report.json');
    expect(b.files.find((f) => f.name === 'dast/probes.json')?.absolutePath).toBe(join(runDir, 'dast', 'probes.json'));
  });

  it('explains itself in plain language, and says an AI review is not a pass', () => {
    const readme = bundle().entries.find((e) => e.name === 'README.txt')!.content;
    expect(readme).toContain('Bookings');
    expect(readme).toContain('run-1');
    expect(readme).toContain('ai-assessed');
    expect(readme).toContain('not "pass"');
    // Every file in the pack is listed in the README.
    for (const name of ['findings.json', 'tool-coverage.json', 'run.json', 'scanners/sast.json']) expect(readme).toContain(name);
  });

  it('names the download after the app and the build, with nothing awkward in the file name', () => {
    expect(scanDataFileName('Bookings', 'run-1')).toBe('Bookings-scan-data-run-1.zip');
    expect(scanDataFileName('My app / v2', 'run-9')).toBe('My-app-v2-scan-data-run-9.zip');
    expect(scanDataFileName('***', 'run-9')).toBe('app-scan-data-run-9.zip');
  });
});
