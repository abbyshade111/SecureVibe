/**
 * renderReports (CONTRACTS §9.6, DESIGN §13.12): writes every report artifact to `outDir` and returns the
 * `ArtifactRef[]` the pipeline records against the run.
 *
 * `renderReports` matches the public contract other modules already call (`../reports-contract.ts`, owned by the
 * integration module): it is deliberately loose (`compliance`/`provenance` optional, no `testResults`/
 * `probeResults`/`sbomPath` fields) because those did not exist when it was written. This file adapts that input
 * into the fuller `ReportModel` the section renderers need, with honest fallbacks when a piece is missing, and
 * also exports `renderReportsFromModel` for a caller that already has the richer shape (testResults, probeResults,
 * a known sbomPath, a resolved profile) and wants to skip the guesswork.
 */
import { existsSync } from 'node:fs';
import { copyFile, mkdir, stat, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import { DesignProfileSchema, type DesignProfile } from '@shared/profile.js';
import type { ArtifactRef, StageResult } from '@shared/pipeline.js';
import { loadFrameworks, loadKnowledge } from '../frameworks/index.js';
import type { ProbeResultLike, TestResult } from '../compliance/types.js';
import type { RenderReportsInput, RenderReportsResult } from '../reports-contract.js';
import { renderComplianceReport } from './compliance-report.js';
import { renderDesignDoc } from './design-doc.js';
import { renderGoingOnline, needsGoingOnline } from './going-online.js';
import { renderOverview } from './overview.js';
import { renderProvenanceJson } from './provenance.js';
import { renderRunLog } from './run-log.js';
import { buildSarif } from './sarif.js';
import { renderSecurityReport } from './security-report.js';
import type { ReportModel } from './types.js';

/** Best-effort extraction of a stage's structured details, tolerant of the field the pipeline actually used. */
function detailsArray<T>(stages: StageResult[], stageId: string, keys: string[]): T[] {
  const stage = stages.find((s) => s.id === stageId);
  const details = stage?.details as Record<string, unknown> | undefined;
  if (!details) return [];
  for (const key of keys) {
    const value = details[key];
    if (Array.isArray(value)) return value as T[];
  }
  return [];
}

function deriveTestResults(stages: StageResult[]): TestResult[] {
  return detailsArray<TestResult>(stages, 'unit-tests', ['tests', 'testResults', 'results']);
}

function deriveProbeResults(stages: StageResult[]): ProbeResultLike[] {
  return detailsArray<ProbeResultLike>(stages, 'dast', ['probes', 'probeResults', 'results']);
}

function deriveProfile(input: RenderReportsInput): DesignProfile | undefined {
  const parsed = DesignProfileSchema.safeParse(input.project.profile);
  return parsed.success ? parsed.data : undefined;
}

async function findSbom(appDir: string | undefined, outDir: string): Promise<string | undefined> {
  const dest = join(outDir, 'sbom.cdx.json');
  // The dependency stage writes the bill of materials straight into the run's reports folder.
  if (existsSync(dest)) return 'sbom.cdx.json';
  if (!appDir) return undefined;
  const source = join(appDir, 'sbom.cdx.json');
  if (!existsSync(source)) return undefined;
  await copyFile(source, dest);
  return 'sbom.cdx.json';
}

/** Copies any raw evidence excerpt file into outDir/evidence/ so reports link to files instead of inlining them. */
async function copyRawEvidence(evidence: Evidence[], outDir: string): Promise<void> {
  const withArtifacts = evidence.filter((e) => e.raw?.artifactPath && existsSync(e.raw.artifactPath));
  if (withArtifacts.length === 0) return;
  const evidenceDir = join(outDir, 'evidence');
  await mkdir(evidenceDir, { recursive: true });
  for (const e of withArtifacts) {
    try {
      await copyFile(e.raw!.artifactPath!, join(evidenceDir, `${e.id}-${basename(e.raw!.artifactPath!)}`));
    } catch {
      // Best effort only: a missing or unreadable raw artifact never fails report generation.
    }
  }
}

function allEvidence(model: ReportModel): Evidence[] {
  return [...model.compliance.asvs.results, ...(model.compliance.aisvs?.results ?? []), ...(model.compliance.appendixC?.results ?? [])].flatMap((r) => r.evidence);
}

async function writeFileArtifact(outDir: string, name: string, content: string, kind: ArtifactRef['kind'], format: ArtifactRef['format'], description: string): Promise<ArtifactRef> {
  const path = join(outDir, name);
  await writeFile(path, content, 'utf8');
  const s = await stat(path);
  // ArtifactRef.path is relative to the project folder: reports live in <project>/reports/<runId>/.
  return { name, path: `reports/${basename(outDir)}/${name}`, kind, format, sizeBytes: s.size, description };
}

/** The fuller entry point: use this when the caller already has testResults/probeResults/profile/sbomPath in hand. */
export async function renderReportsFromModel(model: ReportModel): Promise<RenderReportsResult> {
  await mkdir(model.outDir, { recursive: true });
  await copyRawEvidence(allEvidence(model), model.outDir);

  const artifacts: ArtifactRef[] = [];

  artifacts.push(
    await writeFileArtifact(model.outDir, 'overview.html', renderOverview(model), 'overview', 'html', 'Plain-language summary: can I use it, top actions, scorecards.'),
  );

  const compliance = renderComplianceReport(model);
  artifacts.push(await writeFileArtifact(model.outDir, 'compliance-report.html', compliance.html, 'compliance-report', 'html', 'Full compliance report (ASVS, AISVS, Secure by Design, Appendix C).'));
  artifacts.push(await writeFileArtifact(model.outDir, 'compliance-report.md', compliance.md, 'compliance-report', 'md', 'Compliance report in Markdown.'));
  artifacts.push(await writeFileArtifact(model.outDir, 'compliance-report.json', compliance.json, 'compliance-report', 'json', 'Compliance report data (source of truth).'));

  const security = renderSecurityReport(model);
  artifacts.push(await writeFileArtifact(model.outDir, 'security-report.html', security.html, 'security-report', 'html', 'Every finding with what it is, why it matters and how to fix it.'));
  artifacts.push(await writeFileArtifact(model.outDir, 'security-report.md', security.md, 'security-report', 'md', 'Security report in Markdown.'));
  artifacts.push(await writeFileArtifact(model.outDir, 'security-report.json', security.json, 'security-report', 'json', 'Security report data (findings, coverage, probes, tests).'));

  artifacts.push(await writeFileArtifact(model.outDir, 'design.md', renderDesignDoc(model), 'design-doc', 'md', 'The design document (Secure by Design steps 1-8).'));

  if (needsGoingOnline(model)) {
    const goingOnline = renderGoingOnline(model);
    artifacts.push(await writeFileArtifact(model.outDir, 'going-online.md', goingOnline.md, 'going-online-checklist', 'md', 'What to do before this app is reachable beyond this computer.'));
    artifacts.push(await writeFileArtifact(model.outDir, 'going-online.html', goingOnline.html, 'going-online-checklist', 'html', 'Going-online checklist.'));
  }

  const sarif = JSON.stringify(buildSarif(model.findings, model.securevibeVersion), null, 2);
  artifacts.push(await writeFileArtifact(model.outDir, 'findings.sarif', sarif, 'sarif', 'sarif', 'Findings in SARIF 2.1.0, for editors and CI tools that understand it.'));

  artifacts.push(await writeFileArtifact(model.outDir, 'provenance.json', renderProvenanceJson(model.provenance), 'provenance', 'json', 'Who/what produced this build: model, prompts, approvals, hashes.'));

  artifacts.push(await writeFileArtifact(model.outDir, 'run-log.txt', renderRunLog(model.run), 'run-log', 'txt', 'Plain-text record of every pipeline stage for this run.'));

  if (model.sbomPath) {
    const s = await stat(join(model.outDir, model.sbomPath));
    artifacts.push({ name: model.sbomPath, path: `reports/${basename(model.outDir)}/${model.sbomPath}`, kind: 'sbom', format: 'json', sizeBytes: s.size, description: 'Software bill of materials (CycloneDX).' });
  }

  return { artifacts };
}

/** Matches the existing integration contract: adapts its looser input into a full ReportModel, then renders. */
export async function renderReports(input: RenderReportsInput): Promise<RenderReportsResult> {
  const knowledge = input.knowledge ?? loadKnowledge();
  const frameworks = input.frameworks ?? loadFrameworks();
  const profile = deriveProfile(input);
  const provenance =
    input.provenance ??
    input.run.provenance ?? {
      reportSchemaVersion: '1.0.0',
      tool: `SecureVibe ${input.securevibeVersion}`,
      securevibeVersion: input.securevibeVersion,
      templateVersion: 'unknown',
      frameworkVersions: { asvs: frameworks.asvs.version, aisvs: frameworks.aisvs.version, sbd: frameworks.sbd.version },
      toolVersions: {},
      runId: input.run.id,
      projectId: input.project.id,
      generatedAt: input.run.finishedAt ?? input.run.startedAt,
      mode: input.run.mode,
      humanInvolvement: { summary: 'Not recorded for this run.', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
      designProfileHash: input.project.profileHash ?? '',
      designHash: input.design.profileHash,
      codeTreeHash: '',
      generatedFiles: [],
      recipes: [],
      protectedFileHashes: {},
      sandbox: { mode: 'node-permission-model', note: "Generated code runs under Node's permission model restricted to the project folder; network access is not restricted." },
    };

  if (!input.compliance) {
    // Compliance did not run (or the run crashed before it could): still produce what is honestly possible.
    await mkdir(input.outDir, { recursive: true });
    const runLog = await writeFileArtifact(input.outDir, 'run-log.txt', renderRunLog(input.run), 'run-log', 'txt', 'Plain-text record of every pipeline stage for this run.');
    const provenanceArtifact = await writeFileArtifact(input.outDir, 'provenance.json', renderProvenanceJson(provenance), 'provenance', 'json', 'Who/what produced this build.');
    const sarif = JSON.stringify(buildSarif(input.findings, input.securevibeVersion), null, 2);
    const sarifArtifact = await writeFileArtifact(input.outDir, 'findings.sarif', sarif, 'sarif', 'sarif', 'Findings in SARIF 2.1.0.');
    return { artifacts: [runLog, provenanceArtifact, sarifArtifact] };
  }

  await mkdir(input.outDir, { recursive: true });
  const model: ReportModel = {
    project: input.project,
    design: input.design,
    profile,
    run: input.run,
    compliance: input.compliance,
    findings: input.findings,
    coverage: input.coverage,
    probeResults: deriveProbeResults(input.stages),
    testResults: deriveTestResults(input.stages),
    sbomPath: await findSbom(input.appDir, input.outDir),
    provenance,
    knowledge,
    appDir: input.appDir ?? '',
    outDir: input.outDir,
    securevibeVersion: input.securevibeVersion,
  };
  return renderReportsFromModel(model);
}

export type { ReportModel } from './types.js';
export { renderComplianceReport } from './compliance-report.js';
export { renderSecurityReport } from './security-report.js';
export { renderOverview } from './overview.js';
export { renderGoingOnline, needsGoingOnline } from './going-online.js';
export { renderDesignDoc } from './design-doc.js';
export { buildSarif } from './sarif.js';
export { renderProvenanceJson } from './provenance.js';
export { renderRunLog } from './run-log.js';
