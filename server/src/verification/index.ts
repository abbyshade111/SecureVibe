/**
 * Human verification (ASVS "manual" requirements, AISVS Appendix C AC.4.1/AC.4.4): what a person needs to review,
 * whether a recorded code review still matches the code, and refreshing a build's reports with the answers people
 * gave, without running any check or AI again.
 */
import { existsSync, readFileSync } from 'node:fs';
import { summariseCodeCoverage } from '../compliance/code-coverage.js';
import { DEFAULT_IGNORE, listAppFiles } from '../scanners/sast/files.js';
import { join } from 'node:path';
import { isUploadedApp, type Project } from '@shared/project.js';
import { UPLOADED_REVIEW_GLOBS } from '../api/uploads.js';
import type { PipelineRun } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import type { SecureVibeConfig } from '../config.js';
import type { EvaluateInput } from '../compliance/types.js';
import { evaluateCompliance, renderReports, type Frameworks, type Knowledge } from '../integration.js';
import { listFiles, matchesAnyGlob, sha256File } from '../generator/files.js';
import { summaryOf } from '../pipeline/persist.js';
import { writeJsonAtomicSync, type ProjectStore } from '../store/index.js';
import { createHash } from 'node:crypto';

/** The project the self-assessment CLI keeps its runs in. */
export const SELF_PROJECT_NAME = 'SecureVibe self-assessment';

/** SecureVibe's own security-critical files: what a person should read for its human code review. */
export const SECUREVIBE_REVIEW_GLOBS = [
  'server/src/security/**',
  'server/src/api/**',
  'server/src/app.ts',
  'server/src/main.ts',
  'server/src/config.ts',
  'server/src/llm/anthropic.ts',
  'server/src/llm/agent-loop.ts',
  'server/src/llm/tools.ts',
  'server/src/llm/screening.ts',
  'server/src/llm/redaction.ts',
  'server/src/pipeline/process.ts',
  'server/src/store/paths.ts',
  'server/src/store/atomic.ts',
];

export interface ReviewScope {
  root: string;
  globs: string[];
}

/** Where the security-critical files of this project are, or undefined when there is nothing built to review. */
export function reviewScope(project: Pick<Project, 'id' | 'name' | 'origin'>, store: ProjectStore, config: Pick<SecureVibeConfig, 'paths'>): ReviewScope | undefined {
  if (project.name === SELF_PROJECT_NAME) return { root: config.paths.repoRoot, globs: SECUREVIBE_REVIEW_GLOBS };
  const { appDir } = store.paths(project.id);
  if (isUploadedApp(project)) return existsSync(appDir) ? { root: appDir, globs: UPLOADED_REVIEW_GLOBS } : undefined;
  const manifestFile = join(appDir, 'securevibe.manifest.json');
  if (!existsSync(manifestFile)) return undefined;
  try {
    const manifest = JSON.parse(readFileSync(manifestFile, 'utf8')) as { protectedPaths?: string[] };
    return manifest.protectedPaths?.length ? { root: appDir, globs: manifest.protectedPaths } : undefined;
  } catch {
    return undefined;
  }
}

/** The files in scope and one hash over their contents. Only the folders the patterns name are walked. */
export function reviewTree(scope: ReviewScope): { hash: string; files: string[] } {
  const prefixes = new Set(
    scope.globs.map((g) => {
      const staticPart = g.split('/').filter((_, i, parts) => !parts.slice(0, i + 1).some((p) => /[*?[{]/.test(p)));
      // A plain file pattern: walk its folder.
      return /[*?[{]/.test(g) ? staticPart.join('/') : staticPart.slice(0, -1).join('/');
    }),
  );
  const seen = new Map<string, string>();
  for (const prefix of prefixes) {
    const base = prefix ? join(scope.root, prefix) : scope.root;
    for (const f of listFiles(base)) {
      const rel = prefix ? `${prefix}/${f.relPath}` : f.relPath;
      if (matchesAnyGlob(rel, scope.globs)) seen.set(rel, f.absPath);
    }
  }
  const files = [...seen.keys()].sort();
  const hash = createHash('sha256');
  for (const rel of files) hash.update(`${rel}:${sha256File(seen.get(rel)!) ?? ''}\n`);
  return { hash: hash.digest('hex'), files };
}

/** True when the recorded code review covers exactly the files as they are now. */
export function reviewIsCurrent(project: Project, store: ProjectStore, config: Pick<SecureVibeConfig, 'paths'>): boolean {
  const review = project.humanCodeReview;
  const scope = reviewScope(project, store, config);
  if (!review || !scope) return false;
  return review.codeTreeHash === reviewTree(scope).hash;
}

// --- Refreshing reports with people's answers -------------------------------------------------------------------

/** What the compliance evaluation used, apart from what people provide (attestations, the code review). */
export type SavedComplianceInputs = Omit<EvaluateInput, 'design' | 'profile' | 'knowledge' | 'frameworks' | 'attestations' | 'humanReview'>;

const INPUTS_FILE = 'compliance-inputs.json';

export function saveComplianceInputs(store: ProjectStore, projectId: string, runId: string, inputs: SavedComplianceInputs): void {
  writeJsonAtomicSync(join(store.runDir(projectId, runId), INPUTS_FILE), inputs);
}

export function loadComplianceInputs(store: ProjectStore, projectId: string, runId: string): SavedComplianceInputs | undefined {
  const file = join(store.runDir(projectId, runId), INPUTS_FILE);
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as SavedComplianceInputs;
  } catch {
    return undefined;
  }
}

export class RefreshUnavailableError extends Error {}

export interface RefreshDeps {
  store: ProjectStore;
  config: SecureVibeConfig;
  knowledge: Knowledge;
  frameworks: Frameworks;
}

/**
 * Re-scores the latest build with the answers and code review recorded since, and rewrites its reports. Every
 * automated result stays exactly as it was: nothing is scanned, tested or sent to the AI again.
 */
export async function refreshReportsWithAnswers(deps: RefreshDeps, projectId: string): Promise<PipelineRun> {
  const project = deps.store.mustGet(projectId);
  const run = project.lastRunId ? deps.store.readRun(project.id, project.lastRunId) : undefined;
  if (!run || !project.design) throw new RefreshUnavailableError('This app has no finished build to refresh yet.');
  const inputs = loadComplianceInputs(deps.store, project.id, run.id);
  if (!inputs) {
    throw new RefreshUnavailableError(
      'This build was made before SecureVibe could refresh reports on its own. Run a free check with AI switched off (Settings) once; after that your answers can be added to the reports at any time.',
    );
  }
  const current = reviewIsCurrent(project, deps.store, deps.config);
  /**
   * Worked out again from the app folder, because it is not in the saved inputs: it is a fact about the code on
   * disk rather than about what the scanners returned. Without this, rewriting the reports re-derived the old
   * headline — an app whose code was never read went back to being scored "0 of 106 verified" the moment
   * somebody pressed the button that only rewrites the reports. The fix would have looked like it had not
   * worked, which is worse than the fix not existing.
   */
  const codeCoverage = summariseCodeCoverage(
    listAppFiles(deps.store.paths(project.id).appDir, [...DEFAULT_IGNORE]).map((f) => f.relPath),
  );
  const evaluation = await evaluateCompliance({
    ...inputs,
    codeCoverage,
    design: project.design,
    ...(project.profile ? { profile: project.profile as DesignProfile } : {}),
    attestations: project.attestations,
    ...(project.humanCodeReview && current ? { humanReview: project.humanCodeReview } : {}),
    knowledge: deps.knowledge,
    frameworks: deps.frameworks,
  });
  if (!evaluation.ok) throw new Error(evaluation.reason);
  const evaluated = evaluation.result;
  run.compliance = evaluated;

  const outcome = await renderReports({
    project,
    run,
    design: project.design,
    manifest: inputs.manifest,
    ...(run.provenance ? { provenance: run.provenance } : {}),
    findings: run.findings,
    compliance: evaluated,
    coverage: run.coverage,
    ...(run.llmUsage ? { llmUsage: run.llmUsage } : {}),
    stages: run.stages,
    outDir: deps.store.reportsDir(project.id, run.id),
    appDir: inputs.runMeta.appDir,
    knowledge: deps.knowledge,
    frameworks: deps.frameworks,
    securevibeVersion: deps.config.version,
    pdfPageSize: deps.config.settings.get().pdfPageSize,
  });
  if (!outcome.ok) throw new Error(outcome.reason);
  run.artifacts = outcome.result.artifacts;
  run.reportsRefreshedAt = new Date().toISOString();
  await deps.store.writeRun(run);
  deps.store.recordRunSummary(project.id, summaryOf(run));
  return run;
}
