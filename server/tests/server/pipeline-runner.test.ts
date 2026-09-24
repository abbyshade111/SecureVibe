/**
 * Tests the runner's own orchestration (CONTRACTS §9.5) — stage order, persistence, the three failure rules, and
 * cancellation — with every stage function mocked so nothing here depends on a real scanner or a real LLM call.
 */
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { StageId, StageResult } from '@shared/pipeline.js';
import { loadFrameworks, loadKnowledge, createProvider } from '../../src/integration.js';
import { loadConfig } from '../../src/config.js';
import { ProjectStore } from '../../src/store/index.js';
import { habitTracker } from '../fixtures/design/profiles.js';

const passed = (id: StageId, note = ''): StageResult => ({ id, status: 'passed', summary: note || `${id} ok`, round: 0 });
const failed = (id: StageId, note = ''): StageResult => ({ id, status: 'failed', summary: note || `${id} failed`, round: 0 });
const skipped = (id: StageId, note = ''): StageResult => ({ id, status: 'skipped', summary: note || `${id} skipped`, round: 0 });

vi.mock('../../src/pipeline/stages/index.js', () => ({
  loadFrozenDesign: vi.fn((ctx) => {
    ctx.design = ctx.project.design;
    return passed('design-freeze', 'using existing design (verify-only)');
  }),
  runDesignFreeze: vi.fn(async (ctx) => {
    ctx.design = ctx.project.design;
    ctx.buildSpec = ctx.project.design?.buildSpec;
    return passed('design-freeze');
  }),
  runScaffold: vi.fn(async () => passed('scaffold')),
  runGenerate: vi.fn(async () => ({ result: passed('generate') })),
  runInstall: vi.fn(async () => passed('install')),
  runTypecheck: vi.fn(async () => passed('typecheck')),
  runLintStage: vi.fn(async () => passed('lint')),
  runUnitTestsStage: vi.fn(async () => passed('unit-tests')),
  runSastStage: vi.fn(async () => passed('sast')),
  runSecretsStage: vi.fn(async () => passed('secrets')),
  runDepsStage: vi.fn(async () => passed('deps')),
  runConfigStage: vi.fn(async () => passed('config')),
  runDastStage: vi.fn(async () => passed('dast')),
  runExternalStage: vi.fn(async () => passed('external')),
  runAiReviewStage: vi.fn(async () => passed('ai-review')),
  runComplianceStage: vi.fn(async () => passed('compliance')),
  runReportsStage: vi.fn(async () => passed('reports')),
}));

vi.mock('../../src/pipeline/fix-loop.js', () => ({
  runFixLoop: vi.fn(async () => passed('fix')),
}));

const stages = await import('../../src/pipeline/stages/index.js');
const fixLoop = await import('../../src/pipeline/fix-loop.js');
const { startRun, cancelRun, RunBusRegistry } = await import('../../src/pipeline/index.js');

function freshDeps() {
  const home = mkdtempSync(join(tmpdir(), 'securevibe-runner-'));
  const config = loadConfig({ ...process.env, SECUREVIBE_HOME: home });
  const store = new ProjectStore(config.paths.home);
  const knowledge = loadKnowledge();
  const frameworks = loadFrameworks();
  const provider = createProvider({ forceProvider: 'null' });
  const busRegistry = new RunBusRegistry();
  return { home, deps: { store, config, knowledge, frameworks, provider, busRegistry } };
}

describe('pipeline runner', () => {
  let home: string;
  let deps: ReturnType<typeof freshDeps>['deps'];

  beforeEach(() => {
    vi.clearAllMocks();
    ({ home, deps } = freshDeps());
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function makeProject() {
    return deps.store.create({ name: 'Runner test', mode: 'guided', profile: habitTracker });
  }

  it('runs every stage in order for a full build and persists after each one', async () => {
    const project = makeProject();
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 15 }, deps).execute();

    expect(run.status).toBe('succeeded');
    expect(run.stages.map((s) => s.id)).toEqual([
      'design-freeze', 'scaffold', 'generate', 'install', 'typecheck', 'lint', 'unit-tests', 'sast', 'secrets', 'deps', 'config', 'dast', 'external', 'ai-review', 'fix', 'compliance', 'reports',
    ]);
    expect(stages.runDesignFreeze).toHaveBeenCalledTimes(1);
    expect(stages.loadFrozenDesign).not.toHaveBeenCalled();
    expect(fixLoop.runFixLoop).toHaveBeenCalledTimes(1);

    // Persisted after every stage: the run on disk has the same stage count as the final in-memory run.
    const onDisk = deps.store.readRun(project.id, run.id);
    expect(onDisk?.stages.length).toBe(run.stages.length);
    expect(onDisk?.status).toBe('succeeded');
  });

  it('continues a build that stopped while writing, keeping what it wrote and paying only for the rest', async () => {
    const project = makeProject();
    const stopped = {
      id: 'r_20260918120000_aaaaaa',
      projectId: project.id,
      mode: 'full',
      status: 'failed',
      startedAt: '2026-09-18T12:00:00.000Z',
      stages: [{ id: 'generate', status: 'failed', summary: 'stopped part-way', round: 0 }],
      findings: [],
      coverage: [],
    } as never;
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 15, resumeFrom: stopped }, deps).execute();

    // The app is never laid out twice; the writing is paid for again only because it had not finished.
    expect(stages.runScaffold).not.toHaveBeenCalled();
    expect(stages.runGenerate).toHaveBeenCalledTimes(1);
    expect(run.resumedFrom).toBe('r_20260918120000_aaaaaa');
    expect(run.stages.find((s) => s.id === 'scaffold')?.status).toBe('skipped');
    // Checks always run again: a check carried over would describe code that has changed since.
    expect(stages.runSastStage).toHaveBeenCalledTimes(1);
    expect(stages.runComplianceStage).toHaveBeenCalledTimes(1);
  });

  it('hands the writing step the app it is continuing, or it cannot write at all', async () => {
    // The bug this exists for: a continued build skips scaffold, and scaffold is what puts the app's manifest on
    // the context. The manifest was loaded from disk *after* the generate branch, so a resumed run reached the
    // writing step with none and refused — "The application was not ready to be written yet." Resume could
    // therefore never continue a build interrupted while writing, which is the only case it exists for.
    //
    // It survived a full day of green checks because the test above mocks runGenerate and asserts only that it
    // was called. Being called was never the problem. This asserts what it was called *with*.
    const project = makeProject();
    const appDir = deps.store.paths(project.id).appDir;
    mkdirSync(appDir, { recursive: true });
    // The real template's manifest, not a hand-written stand-in: the runner parses it against the schema, and a
    // fixture that drifts from the template would pass here while failing for every actual app.
    copyFileSync(fileURLToPath(new URL('../../../templates/secure-web-app/securevibe.manifest.json', import.meta.url)), join(appDir, 'securevibe.manifest.json'));

    const stopped = {
      id: 'r_20260920000000_cccccc',
      projectId: project.id,
      mode: 'full',
      status: 'canceled',
      startedAt: '2026-09-20T00:00:00.000Z',
      stages: [{ id: 'generate', status: 'failed', summary: 'the AI could not be reached', round: 0 }],
      findings: [],
      coverage: [],
    } as never;
    // Captured at the moment of the call, not read from the context afterwards. The context is one mutable
    // object that later stages go on filling in, so inspecting it at the end says what the run eventually knew,
    // not what the writing step was given — and the first version of this test passed with the bug reinstated.
    let manifestAtWritingTime: unknown;
    vi.mocked(stages.runGenerate).mockImplementationOnce(async (ctx: { manifest?: unknown }) => {
      manifestAtWritingTime = ctx.manifest;
      return { result: passed('generate') };
    });
    await startRun(project, { mode: 'full', spendingCapUsd: 15, resumeFrom: stopped }, deps).execute();

    expect(stages.runGenerate).toHaveBeenCalledTimes(1);
    expect(manifestAtWritingTime, 'the writing step was handed no manifest, so the real one would refuse to write').toBeDefined();
  });

  it('pays nothing to write again when the stopped build had finished writing', async () => {
    const project = makeProject();
    const stopped = {
      id: 'r_20260918130000_bbbbbb',
      projectId: project.id,
      mode: 'full',
      status: 'canceled',
      startedAt: '2026-09-18T13:00:00.000Z',
      stages: [{ id: 'generate', status: 'passed', summary: 'written', round: 0 }],
      findings: [],
      coverage: [],
    } as never;
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 15, resumeFrom: stopped }, deps).execute();

    expect(stages.runGenerate).not.toHaveBeenCalled();
    expect(run.stages.find((s) => s.id === 'generate')?.status).toBe('skipped');
    expect(run.stages.find((s) => s.id === 'generate')?.summary).toMatch(/nothing was spent/i);
    // "had finished writing your app" was not always true: on a build without AI the recipes write the app at
    // scaffold time and the writing step is skipped, so nothing ever finished writing. What the owner needs to
    // know is the same either way — there was nothing left to write, so nothing was paid for twice.
    expect(run.resumedNote).toMatch(/nothing left to write/i);
    expect(run.resumedNote).toMatch(/nothing was written again/i);
  });

  it('runs only the checks the owner asked for, and leaves the compliance report alone', async () => {
    const project = makeProject();
    project.design = { ...project.design, profileHash: 'x' } as never;
    const run = await startRun(project, { mode: 'verify-only', spendingCapUsd: 15, onlyChecks: ['sast', 'deps'] }, deps).execute();

    expect(stages.runSastStage).toHaveBeenCalledTimes(1);
    expect(stages.runDepsStage).toHaveBeenCalledTimes(1);
    // Packages are installed anyway: the checks cannot read a project that was never set up.
    expect(stages.runInstall).toHaveBeenCalledTimes(1);
    expect(stages.runDastStage).not.toHaveBeenCalled();
    expect(stages.runConfigStage).not.toHaveBeenCalled();
    // The verdict and the reports are left as the last full check made them, and the run says it was partial.
    expect(stages.runComplianceStage).not.toHaveBeenCalled();
    expect(stages.runReportsStage).not.toHaveBeenCalled();
    expect(run.partial).toBe(true);
    expect(run.partialChecks).toEqual(['sast', 'deps']);
    const dast = run.stages.find((s) => s.id === 'dast');
    expect(dast?.status).toBe('skipped');
    expect(dast?.summary).toMatch(/asked for some of the checks only/i);
    expect(run.stages.find((s) => s.id === 'compliance')?.summary).toMatch(/left as your last full check made it/i);
  });

  it('says it skipped scaffold/generate/fix in verify-only mode, rather than leaving them pending', async () => {
    const project = makeProject();
    project.design = { ...project.design, profileHash: 'x' } as never; // presence is all loadFrozenDesign needs
    const run = await startRun(project, { mode: 'verify-only', spendingCapUsd: 15 }, deps).execute();

    expect(stages.loadFrozenDesign).toHaveBeenCalledTimes(1);
    expect(stages.runDesignFreeze).not.toHaveBeenCalled();
    expect(stages.runScaffold).not.toHaveBeenCalled();
    expect(stages.runGenerate).not.toHaveBeenCalled();
    expect(fixLoop.runFixLoop).not.toHaveBeenCalled();
    // Recorded as skipped, with a reason, rather than left out. A stage with no entry renders as "pending", which
    // reads as work still to come and keeps the progress bar short of the end: an owner watching a free update saw
    // two steps apparently waiting that were never going to happen.
    for (const id of ['scaffold', 'generate', 'fix'] as const) {
      const stage = run.stages.find((s) => s.id === id);
      expect(stage, `${id} was left out of the run instead of being marked skipped`).toBeDefined();
      expect(stage!.status).toBe('skipped');
      expect(stage!.summary).toBeTruthy();
    }
    // The one that costs money says so plainly, because that is the reassurance a free update owes the owner.
    expect(run.stages.find((s) => s.id === 'generate')!.summary).toMatch(/nothing was spent/i);
  });

  it('a design-freeze failure stops the run before scaffold/generate', async () => {
    vi.mocked(stages.runDesignFreeze).mockResolvedValueOnce(failed('design-freeze', 'profile incomplete'));
    const project = makeProject();
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 15 }, deps).execute();

    expect(run.status).toBe('failed');
    expect(run.stages.map((s) => s.id)).toEqual(['design-freeze']);
    expect(stages.runScaffold).not.toHaveBeenCalled();
  });

  it('a generate refusal stops the run immediately, with no further stages', async () => {
    vi.mocked(stages.runGenerate).mockResolvedValueOnce({
      result: failed('generate', 'Claude declined to write this application.'),
      hardStop: { stage: 'generate', message: 'Claude declined to write this application.', options: ['change-answers', 'retry'] },
    });
    const project = makeProject();
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 15 }, deps).execute();

    expect(run.status).toBe('failed');
    expect(run.failure?.message).toMatch(/declined/);
    expect(run.stages.map((s) => s.id)).toEqual(['design-freeze', 'scaffold', 'generate']);
    expect(stages.runInstall).not.toHaveBeenCalled();
    expect(stages.runComplianceStage).not.toHaveBeenCalled();
  });

  it('a stage that throws is marked failed, the remaining scan stages are skipped, and compliance+reports still run', async () => {
    vi.mocked(stages.runSastStage).mockRejectedValueOnce(new Error('sast crashed'));
    const project = makeProject();
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 15 }, deps).execute();

    expect(run.incomplete).toBe(true);
    const byId = new Map(run.stages.map((s) => [s.id, s]));
    expect(byId.get('sast')?.status).toBe('failed');
    expect(byId.get('secrets')?.status).toBe('skipped');
    expect(byId.get('deps')?.status).toBe('skipped');
    expect(byId.get('ai-review')?.status).toBe('skipped');
    expect(byId.get('compliance')?.status).toBe('passed'); // still ran, per CONTRACTS §9.5
    expect(byId.get('reports')?.status).toBe('passed');
    expect(run.status).toBe('failed');
  });

  it('canceling mid-run stops the remaining core stages and marks the run canceled', async () => {
    const project = makeProject();
    const started = startRun(project, { mode: 'full', spendingCapUsd: 15 }, deps);
    vi.mocked(stages.runInstall).mockImplementationOnce(async () => {
      cancelRun(started.run.id);
      return passed('install');
    });

    const run = await started.execute();
    expect(run.status).toBe('canceled');
    expect(stages.runTypecheck).not.toHaveBeenCalled();
    expect(fixLoop.runFixLoop).not.toHaveBeenCalled();
    expect(stages.runComplianceStage).toHaveBeenCalledTimes(1); // still evaluated with whatever was found
  });

  it('records the owner approval given on the build page, with what was shown', async () => {
    const project = makeProject();
    const approval = {
      approvedBy: 'owner (signed-in session abc123def456)',
      approvedAt: '2026-09-17T12:00:00.000Z',
      sessionRef: 'abc123def456',
      designHash: 'hash-1',
      estimateUsdHigh: 4.5,
      estimateShownAt: '2026-09-17T11:58:00.000Z',
      spendingCapUsd: 10,
    };
    const run = await startRun(project, { mode: 'full', spendingCapUsd: 10, approval }, deps).execute();
    expect(run.approvedBy).toBe(approval.approvedBy);
    expect(run.approvedAt).toBe(approval.approvedAt);
    expect(run.approval).toEqual({ sessionRef: 'abc123def456', designHash: 'hash-1', estimateUsdHigh: 4.5, estimateShownAt: approval.estimateShownAt, spendingCapUsd: 10 });
  });

  it('records no approval for a run nobody approved', async () => {
    const run = await startRun(makeProject(), { mode: 'full', spendingCapUsd: 10 }, deps).execute();
    expect(run.approvedBy).toBeUndefined();
    expect(run.approvedAt).toBeUndefined();
    expect(run.approval).toBeUndefined();
  });

  it('marks the app built when a run succeeds, and clears the "rebuild needed" flag', async () => {
    const project = makeProject();
    deps.store.update(project.id, (p) => {
      p.status = 'designed';
      p.buildStale = true;
      p.designStale = true;
    });
    const started = startRun(project, { mode: 'full', spendingCapUsd: 10 }, deps);
    expect(deps.store.mustGet(project.id).status).toBe('building');
    const run = await started.execute();
    expect(run.status).toBe('succeeded');
    const after = deps.store.mustGet(project.id);
    expect(after).toMatchObject({ status: 'built', buildStale: false, designStale: false });
  });

  it('marks the app failed when the run fails, and leaves it usable after a cancel', async () => {
    vi.mocked(stages.runDesignFreeze).mockResolvedValueOnce(failed('design-freeze', 'profile incomplete'));
    const failedRun = await startRun(makeProject(), { mode: 'full', spendingCapUsd: 10 }, deps).execute();
    expect(failedRun.status).toBe('failed');
    expect(deps.store.mustGet(failedRun.projectId).status).toBe('failed');

    const project = makeProject();
    const started = startRun(project, { mode: 'full', spendingCapUsd: 10 }, deps);
    cancelRun(started.run.id);
    await started.execute();
    // Nothing was built yet, so the app goes back to "design ready" rather than staying "building".
    expect(deps.store.mustGet(project.id).status).toBe('designed');
  });

  it('cancelRun returns false for a run that is not active', () => {
    expect(cancelRun('r_00000000000000_aaaaaa')).toBe(false);
  });
});
