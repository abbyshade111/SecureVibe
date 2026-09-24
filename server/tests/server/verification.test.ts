import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ComplianceResult } from '@shared/compliance.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { loadConfig, type SecureVibeConfig } from '../../src/config.js';
import { deriveDesign } from '../../src/design/index.js';
import { evaluateCompliance, loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { ProjectStore } from '../../src/store/index.js';
import {
  loadComplianceInputs,
  refreshReportsWithAnswers,
  RefreshUnavailableError,
  reviewIsCurrent,
  reviewScope,
  reviewTree,
  saveComplianceInputs,
  SELF_PROJECT_NAME,
  type SavedComplianceInputs,
} from '../../src/verification/index.js';
import { manifestFixture } from '../fixtures/compliance/manifest.js';
import { habitTracker } from '../fixtures/design/profiles.js';

const knowledge = loadKnowledge();
const allResults = (c: ComplianceResult) => [...c.asvs.results, ...(c.aisvs?.results ?? []), ...(c.appendixC?.results ?? [])];
const frameworks = loadFrameworks();

describe('human verification', () => {
  let home: string;
  let config: SecureVibeConfig;
  let store: ProjectStore;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'securevibe-verify-'));
    config = loadConfig({ ...process.env, SECUREVIBE_HOME: home });
    store = new ProjectStore(config.paths.home);
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  async function builtProject(withInputs: boolean) {
    const project = store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const design = deriveDesign(habitTracker, { knowledge, frameworks });
    store.update(project.id, (p) => {
      p.design = design;
    });
    const runId = 'r_20260917120000_abcdef';
    const inputs: SavedComplianceInputs = {
      manifest: manifestFixture,
      manifestResults: [],
      findings: [],
      evidence: [],
      testResults: [],
      probeResults: [],
      runMeta: { runId, mode: 'full', provider: 'null', model: 'none', appDir: store.paths(project.id).appDir, stages: [], coverage: [], incomplete: false, fixRounds: 0 },
    };
    const evaluated = await evaluateCompliance({ ...inputs, design, profile: habitTracker, attestations: [], knowledge, frameworks });
    if (!evaluated.ok) throw new Error(evaluated.reason);
    const run = {
      id: runId,
      projectId: project.id,
      mode: 'full',
      startedAt: '2026-09-17T12:00:00.000Z',
      finishedAt: '2026-09-17T12:05:00.000Z',
      status: 'succeeded',
      stages: [],
      findings: [],
      coverage: [],
      artifacts: [],
      fixRounds: 0,
      incomplete: false,
      spendingCapUsd: 5,
      compliance: evaluated.result,
    } as unknown as PipelineRun;
    store.writeRunSync(run);
    store.update(project.id, (p) => {
      p.lastRunId = runId;
    });
    if (withInputs) saveComplianceInputs(store, project.id, runId, inputs);
    return { project: store.mustGet(project.id), run, compliance: evaluated.result };
  }

  it('adds an answer to the reports without running anything again', async () => {
    const { project, compliance } = await builtProject(true);
    const ownerItem = compliance.manualVerification.find((m) => m.manual.whoCanDo === 'owner');
    expect(ownerItem).toBeDefined();
    const before = allResults(compliance).find((r) => r.id === ownerItem!.requirementId)!;
    expect(before.assessedBy).not.toContain('manual');

    store.addAttestation(project.id, { requirementId: ownerItem!.requirementId, standard: ownerItem!.standard, result: 'yes', note: 'Checked with the team.', attestedBy: 'Sam Rivera' });
    const run = await refreshReportsWithAnswers({ store, config, knowledge, frameworks }, project.id);

    const after = allResults(run.compliance!).find((r) => r.id === ownerItem!.requirementId)!;
    expect(after.assessedBy).toContain('manual');
    expect(after.evidence.some((e) => e.summary === 'Checked with the team.')).toBe(true);
    expect(run.reportsRefreshedAt).toBeDefined();
    expect(run.artifacts.some((a) => a.name === 'compliance-report.html')).toBe(true);
    expect(store.readRun(project.id, run.id)!.reportsRefreshedAt).toBe(run.reportsRefreshedAt);
  });

  it('keeps a "not sure" answer as still to be checked, and a "no" as a fail', async () => {
    const { project, compliance } = await builtProject(true);
    const items = compliance.manualVerification.filter((m) => m.manual.whoCanDo === 'owner').slice(0, 2);
    expect(items).toHaveLength(2);
    const [unsure, no] = items as [(typeof items)[0], (typeof items)[0]];
    const statusBefore = allResults(compliance).find((r) => r.id === unsure.requirementId)!.status;
    store.addAttestation(project.id, { requirementId: unsure.requirementId, standard: unsure.standard, result: 'not-sure', note: '', attestedBy: 'Sam' });
    store.addAttestation(project.id, { requirementId: no.requirementId, standard: no.standard, result: 'no', note: '', attestedBy: 'Sam' });
    const run = await refreshReportsWithAnswers({ store, config, knowledge, frameworks }, project.id);
    expect(allResults(run.compliance!).find((r) => r.id === unsure.requirementId)!.status).toBe(statusBefore);
    expect(allResults(run.compliance!).find((r) => r.id === no.requirementId)!.status).toBe('fail');
  });

  it('records "not applicable" with its reason, who decided and when, and stops counting the rule', async () => {
    const { project, compliance } = await builtProject(true);
    const item = compliance.manualVerification.find((m) => m.manual.whoCanDo === 'owner')!;
    store.addAttestation(project.id, {
      requirementId: item.requirementId,
      standard: item.standard,
      result: 'not-applicable',
      note: 'Nobody outside this household ever signs in; there is no organization and no central sign-in system.',
      attestedBy: 'Sam Rivera',
    });
    const run = await refreshReportsWithAnswers({ store, config, knowledge, frameworks }, project.id);
    const result = allResults(run.compliance!).find((r) => r.id === item.requirementId)!;
    expect(result.status).toBe('not-applicable');
    expect(result.rationale).toContain('because Nobody outside this household ever signs in');
    expect(result.rationale).toContain('Sam Rivera');
    expect(result.rationale).toMatch(/owner's decision, not verified/);
  });

  it('explains when a build is too old to refresh', async () => {
    const { project } = await builtProject(false);
    expect(loadComplianceInputs(store, project.id, project.lastRunId!)).toBeUndefined();
    await expect(refreshReportsWithAnswers({ store, config, knowledge, frameworks }, project.id)).rejects.toBeInstanceOf(RefreshUnavailableError);
  });

  it('knows which files a person must read, and when a recorded review goes stale', () => {
    const project = store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    expect(reviewScope(project, store, config)).toBeUndefined();

    const { appDir } = store.paths(project.id);
    mkdirSync(join(appDir, 'src', 'security'), { recursive: true });
    writeFileSync(join(appDir, 'securevibe.manifest.json'), JSON.stringify({ protectedPaths: ['src/security/**', 'src/app.ts'] }));
    writeFileSync(join(appDir, 'src', 'security', 'csrf.ts'), 'export {};\n');
    writeFileSync(join(appDir, 'src', 'app.ts'), 'export {};\n');
    writeFileSync(join(appDir, 'src', 'other.ts'), 'export {};\n');

    const scope = reviewScope(project, store, config)!;
    const tree = reviewTree(scope);
    expect(tree.files).toEqual(['src/app.ts', 'src/security/csrf.ts']);

    const reviewed = store.setHumanCodeReview(project.id, { reviewedBy: 'Sam', reviewedAt: '2026-09-17T12:00:00.000Z', filesReviewed: tree.files, codeTreeHash: tree.hash });
    expect(reviewIsCurrent(reviewed, store, config)).toBe(true);
    writeFileSync(join(appDir, 'src', 'other.ts'), 'export const x = 1;\n');
    expect(reviewIsCurrent(reviewed, store, config)).toBe(true);
    writeFileSync(join(appDir, 'src', 'security', 'csrf.ts'), 'export const changed = true;\n');
    expect(reviewIsCurrent(reviewed, store, config)).toBe(false);
  });

  it("reviews SecureVibe's own security-critical files for the self-assessment", () => {
    const project = store.create({ name: SELF_PROJECT_NAME, mode: 'quick', profile: habitTracker });
    const scope = reviewScope(project, store, config)!;
    expect(scope.root).toBe(config.paths.repoRoot);
    const { files } = reviewTree(scope);
    expect(files).toContain('server/src/security/token.ts');
    expect(files).toContain('server/src/app.ts');
    expect(files.some((f) => f.startsWith('server/tests/') || f.includes('node_modules'))).toBe(false);
  });
});
