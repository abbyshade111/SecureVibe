import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { renderReports, renderReportsFromModel } from '../../src/reports/index.js';
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
        'compliance-report.html',
        'compliance-report.md',
        'compliance-report.json',
        'security-report.html',
        'security-report.md',
        'security-report.json',
        'design.md',
        'going-online.md',
        'going-online.html',
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

  it('degrades honestly (still writes provenance/run-log/sarif) when compliance is missing', async () => {
    const { artifacts } = await renderReports(contractInput({ compliance: undefined }));
    const names = artifacts.map((a) => a.name).sort();
    expect(names).toEqual(['findings.sarif', 'provenance.json', 'run-log.txt']);
  });
});
