import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { renderReports, renderReportsFromModel, renderReportsWithoutAnswers } from '../../src/reports/index.js';
import type { ReportModel } from '../../src/reports/types.js';
import type { RenderReportsInput } from '../../src/reports-contract.js';
import { buildReportModel } from '../fixtures/reports/model.js';

let dir: string;
let model: ReportModel;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securevibe-reports-index-'));
  model = await buildReportModel(join(dir, 'reports'), join(dir, 'app'));
  await mkdir(model.appDir, { recursive: true });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('renderReportsFromModel', () => {
  it('writes every required artifact to outDir and returns matching ArtifactRefs', async () => {
    const { artifacts } = await renderReportsFromModel(model);
    const names = artifacts.map((a) => a.name).sort();
    expect(names).toEqual(
      [
        'overview.html',
        'overview.pdf',
        'compliance-report.html',
        'compliance-report.pdf',
        'compliance-report.md',
        'compliance-report.json',
        'security-report.html',
        'security-report.pdf',
        'security-report.md',
        'security-report.json',
        'design.md',
        'going-online.md',
        'going-online.html',
        'going-online.pdf',
        'findings.sarif',
        'provenance.json',
        'run-log.txt',
      ].sort(),
    );
    for (const a of artifacts) {
      // Paths are relative to the project folder: reports/<runId>/<file>.
      expect(a.path, a.path).toBe(`reports/${basename(model.outDir)}/${a.name}`);
      expect(existsSync(join(model.outDir, a.name)), a.path).toBe(true);
      expect(a.sizeBytes).toBeGreaterThan(0);
    }
  });

  it('writes a PDF beside each HTML report, as a real PDF file, listed with the pdf format', async () => {
    const { artifacts } = await renderReportsFromModel(model);
    const pdfs = artifacts.filter((a) => a.format === 'pdf');
    expect(pdfs.map((a) => a.name).sort()).toEqual(['compliance-report.pdf', 'going-online.pdf', 'overview.pdf', 'security-report.pdf']);
    for (const a of pdfs) {
      const bytes = await readFile(join(model.outDir, a.name));
      expect(bytes.subarray(0, 5).toString('latin1'), a.name).toBe('%PDF-');
      expect(bytes.subarray(-6).toString('latin1'), a.name).toContain('%%EOF');
      expect(a.sizeBytes).toBe(bytes.length);
    }
  });

  it('findings.sarif and compliance-report.json are valid JSON on disk', async () => {
    await renderReportsFromModel(model);
    const sarif = JSON.parse(await readFile(join(model.outDir, 'findings.sarif'), 'utf8'));
    expect(sarif.version).toBe('2.1.0');
    const compliance = JSON.parse(await readFile(join(model.outDir, 'compliance-report.json'), 'utf8'));
    expect(compliance.runId).toBe(model.compliance.runId);
  });

  it('lists an already-placed SBOM (outDir/sbomPath) as an artifact', async () => {
    const withSbom = await buildReportModel(join(dir, 'reports2'), model.appDir);
    await mkdir(withSbom.outDir, { recursive: true });
    await writeFile(join(withSbom.outDir, 'sbom.cdx.json'), JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }));
    const { artifacts } = await renderReportsFromModel({ ...withSbom, sbomPath: 'sbom.cdx.json' });
    const sbom = artifacts.find((a) => a.kind === 'sbom');
    expect(sbom).toBeDefined();
    expect(sbom?.path).toBe(`reports/${basename(withSbom.outDir)}/sbom.cdx.json`);
  });

  it('skips the going-online artifacts for a local-only, just-me app', async () => {
    const localModel: ReportModel = {
      ...model,
      outDir: join(dir, 'reports-local'),
      profile: model.profile ? { ...model.profile, users: { ...model.profile.users, audience: 'just-me' }, deployment: { ...model.profile.deployment, target: 'local-only' } } : undefined,
    };
    const { artifacts } = await renderReportsFromModel(localModel);
    expect(artifacts.some((a) => a.kind === 'going-online-checklist')).toBe(false);
  });
});

describe('renderReports (the public contract other modules already call)', () => {
  function contractInput(overrides: Partial<RenderReportsInput> = {}): RenderReportsInput {
    return {
      project: model.project,
      run: model.run,
      design: model.design,
      provenance: model.provenance,
      findings: model.findings,
      compliance: model.compliance,
      coverage: model.coverage,
      stages: model.run.stages,
      outDir: model.outDir,
      appDir: model.appDir,
      knowledge: model.knowledge,
      frameworks: { asvs: { version: 'x' }, aisvs: { version: 'x' }, sbd: { version: 'x' } } as unknown as RenderReportsInput['frameworks'],
      securevibeVersion: model.securevibeVersion,
      ...overrides,
    };
  }

  it('derives testResults/probeResults from stage details and renders the full report set', async () => {
    const { artifacts } = await renderReports(contractInput());
    expect(artifacts.some((a) => a.name === 'compliance-report.html')).toBe(true);
    const security = artifacts.find((a) => a.name === 'security-report.md')!;
    const content = await readFile(join(model.outDir, security.name), 'utf8');
    // The DAST probe from stages[].details.probes made it into the security report.
    expect(content).toContain('dast.headers.csp');
  });

  it('copies an SBOM found under appDir into outDir and lists it', async () => {
    await writeFile(join(model.appDir, 'sbom.cdx.json'), JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }));
    const { artifacts } = await renderReports(contractInput());
    const sbom = artifacts.find((a) => a.kind === 'sbom');
    expect(sbom).toBeDefined();
    expect(existsSync(join(model.outDir, 'sbom.cdx.json'))).toBe(true);
  });

  it('writes the full security report, SARIF, run log and provenance for a check made without answers, and says why there is no compliance report', async () => {
    // An uploaded app checked before the questions were answered: the answers decide which rules apply, not
    // whether the checks ran, so everything that does not depend on them is written in full.
    const { design: _design, compliance: _compliance, ...rest } = model;
    const { artifacts } = await renderReportsWithoutAnswers({ ...rest, stages: model.run.stages, frameworks: (await import('../../src/frameworks/index.js')).loadFrameworks() });
    const names = artifacts.map((a) => a.name).sort();
    expect(names).toEqual(['overview.html', 'overview.pdf', 'security-report.html', 'security-report.pdf', 'security-report.md', 'security-report.json', 'findings.sarif', 'provenance.json', 'run-log.txt'].sort());
    expect(names).not.toContain('compliance-report.html');
    expect(names).not.toContain('design.md');
    const overview = await readFile(join(model.outDir, 'overview.html'), 'utf8');
    expect(overview).toContain('Which rules apply is not decided yet');
    expect(overview).toContain('security-report.html');
    const security = await readFile(join(model.outDir, 'security-report.html'), 'utf8');
    expect(security).toContain('Provenance');
    for (const a of artifacts) expect(a.sizeBytes, a.name).toBeGreaterThan(0);
  });

  it('degrades honestly (still writes provenance/run-log/sarif) when compliance is missing', async () => {
    const { artifacts } = await renderReports(contractInput({ compliance: undefined }));
    const names = artifacts.map((a) => a.name).sort();
    expect(names).toEqual(['findings.sarif', 'provenance.json', 'run-log.txt']);
  });
});
