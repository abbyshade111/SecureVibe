/**
 * Project persistence (CONTRACTS §9.6):
 *
 *   <home>/projects/<id>/project.json        the Project
 *                        design/             design.json, design.md, security-contract.md, adr/*.md, threat-model.md, diagram.mmd
 *                        app/                the current generated application
 *                        app-v<N>/           previous versions (kept on rebuild)
 *                        pipeline/<runId>/   run.json, stages/*.log, llm/, fixes/, dast/
 *                        reports/<runId>/    rendered reports and downloads
 *
 * Every write is atomic and every path is confined to the workspace root.
 */
import { existsSync, mkdirSync, readdirSync, realpathSync, renameSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { ProjectListItem } from '@shared/api.js';
import type { PipelineRun, RunSummary } from '@shared/pipeline.js';
import { AttestationSchema, ProjectSchema, type Attestation, type FindingDecision, type HumanCodeReview, type Project } from '@shared/project.js';
import { PipelineRunSchema } from '@shared/pipeline.js';
import { readJsonFile, writeJsonAtomic, writeJsonAtomicSync } from './atomic.js';
import { isProjectId, isRunId, newAttestationId, newProjectId } from './ids.js';
import { confinePath } from './paths.js';

export interface ProjectPaths {
  dir: string;
  projectJson: string;
  designDir: string;
  appDir: string;
  pipelineDir: string;
  reportsDir: string;
  attestationsJson: string;
}

export class ProjectNotFoundError extends Error {
  constructor(readonly projectId: string) {
    super(`Project ${projectId} was not found.`);
    this.name = 'ProjectNotFoundError';
  }
}

export interface CreateProjectInput {
  name: string;
  mode: 'guided' | 'quick';
  profile?: Project['profile'];
  startedFromExample?: string;
  origin?: Project['origin'];
}

export class ProjectStore {
  readonly projectsDir: string;

  readonly home: string;

  constructor(home: string) {
    mkdirSync(join(home, 'projects'), { recursive: true });
    // The real path: Node's permission model (which fences generated apps) compares real paths, so a workspace
    // reached through a symlink (macOS's /var → /private/var, for one) must be named by where it really is.
    this.home = realpathSync(home);
    this.projectsDir = join(this.home, 'projects');
  }

  // --- paths ------------------------------------------------------------------------------------------------------

  /** Absolute path under the workspace root; throws when the result would escape it. */
  resolve(...segments: string[]): string {
    return confinePath(this.home, ...segments);
  }

  paths(projectId: string): ProjectPaths {
    if (!isProjectId(projectId)) throw new ProjectNotFoundError(projectId);
    const dir = this.resolve('projects', projectId);
    return {
      dir,
      projectJson: join(dir, 'project.json'),
      designDir: join(dir, 'design'),
      appDir: join(dir, 'app'),
      pipelineDir: join(dir, 'pipeline'),
      reportsDir: join(dir, 'reports'),
      attestationsJson: join(dir, 'attestations.json'),
    };
  }

  /** Absolute path inside one project folder, confined to it. */
  projectPath(projectId: string, ...segments: string[]): string {
    const { dir } = this.paths(projectId);
    return confinePath(dir, ...segments);
  }

  runDir(projectId: string, runId: string): string {
    if (!isRunId(runId)) throw new Error(`Invalid run id: ${runId}`);
    return this.projectPath(projectId, 'pipeline', runId);
  }

  reportsDir(projectId: string, runId: string): string {
    if (!isRunId(runId)) throw new Error(`Invalid run id: ${runId}`);
    return this.projectPath(projectId, 'reports', runId);
  }

  // --- projects ---------------------------------------------------------------------------------------------------

  list(): ProjectListItem[] {
    const items: ProjectListItem[] = [];
    for (const name of readdirSync(this.projectsDir)) {
      if (!isProjectId(name)) continue;
      const project = this.get(name);
      if (!project) continue;
      items.push(toListItem(project));
    }
    return items.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  get(projectId: string): Project | undefined {
    if (!isProjectId(projectId)) return undefined;
    const { projectJson } = this.paths(projectId);
    if (!existsSync(projectJson)) return undefined;
    return readJsonFile(projectJson, ProjectSchema);
  }

  mustGet(projectId: string): Project {
    const project = this.get(projectId);
    if (!project) throw new ProjectNotFoundError(projectId);
    return project;
  }

  create(input: CreateProjectInput, now: Date = new Date()): Project {
    let id = newProjectId();
    while (existsSync(this.paths(id).dir)) id = newProjectId();
    const iso = now.toISOString();
    const profile: Project['profile'] = input.profile ? structuredClone(input.profile) : {};
    profile.meta = { ...(profile.meta ?? {}), mode: input.mode, ...(input.startedFromExample ? { startedFromExample: input.startedFromExample } : {}) };
    if (!profile.app) profile.app = {};
    if (!profile.app.name) profile.app.name = input.name;
    const project = ProjectSchema.parse({ id, name: input.name, createdAt: iso, updatedAt: iso, profile, status: 'draft', ...(input.origin ? { origin: input.origin } : {}) });
    const paths = this.paths(id);
    for (const dir of [paths.dir, paths.designDir, paths.pipelineDir, paths.reportsDir]) mkdirSync(dir, { recursive: true });
    writeJsonAtomicSync(paths.projectJson, project);
    return project;
  }

  save(project: Project, now: Date = new Date()): Project {
    const validated = ProjectSchema.parse({ ...project, updatedAt: now.toISOString() });
    const { projectJson, dir } = this.paths(validated.id);
    if (!existsSync(dir)) throw new ProjectNotFoundError(validated.id);
    writeJsonAtomicSync(projectJson, validated);
    return validated;
  }

  /** Read-modify-write helper. */
  update(projectId: string, mutate: (project: Project) => void): Project {
    const project = this.mustGet(projectId);
    mutate(project);
    return this.save(project);
  }

  delete(projectId: string): boolean {
    const { dir } = this.paths(projectId);
    if (!existsSync(dir)) return false;
    rmSync(dir, { recursive: true, force: true });
    return true;
  }

  // --- app versioning ---------------------------------------------------------------------------------------------

  /**
   * Moves app/ to app-v<N>/ before a rebuild and bumps project.appVersion. Returns the archived folder, or
   * undefined when there was no app/ yet.
   */
  archiveApp(projectId: string): { archivedTo?: string; version: number } {
    const project = this.mustGet(projectId);
    const { appDir, dir } = this.paths(projectId);
    if (!existsSync(appDir)) return { version: project.appVersion };
    let version = project.appVersion + 1;
    let target = join(dir, `app-v${version}`);
    while (existsSync(target)) {
      version += 1;
      target = join(dir, `app-v${version}`);
    }
    renameSync(appDir, target);
    project.appVersion = version;
    this.save(project);
    return { archivedTo: target, version };
  }

  // --- runs -------------------------------------------------------------------------------------------------------

  readRun(projectId: string, runId: string): PipelineRun | undefined {
    const file = join(this.runDir(projectId, runId), 'run.json');
    if (!existsSync(file)) return undefined;
    return readJsonFile(file, PipelineRunSchema);
  }

  async writeRun(run: PipelineRun): Promise<void> {
    const dir = this.runDir(run.projectId, run.id);
    mkdirSync(dir, { recursive: true });
    await writeJsonAtomic(join(dir, 'run.json'), run);
  }

  writeRunSync(run: PipelineRun): void {
    const dir = this.runDir(run.projectId, run.id);
    mkdirSync(dir, { recursive: true });
    writeJsonAtomicSync(join(dir, 'run.json'), run);
  }

  listRunIds(projectId: string): string[] {
    const { pipelineDir } = this.paths(projectId);
    if (!existsSync(pipelineDir)) return [];
    return readdirSync(pipelineDir)
      .filter((name) => isRunId(name) && statSync(join(pipelineDir, name)).isDirectory())
      .sort();
  }

  /** Finds a run by id across projects (the runs API is addressed by run id only). */
  findRun(runId: string): PipelineRun | undefined {
    if (!isRunId(runId)) return undefined;
    for (const name of readdirSync(this.projectsDir)) {
      if (!isProjectId(name)) continue;
      const run = this.readRun(name, runId);
      if (run) return run;
    }
    return undefined;
  }

  /** Records a run summary on the project (replacing an earlier summary with the same id). */
  recordRunSummary(projectId: string, summary: RunSummary): Project {
    return this.update(projectId, (project) => {
      project.runs = [...project.runs.filter((r) => r.id !== summary.id), summary].sort((a, b) => a.startedAt.localeCompare(b.startedAt));
      project.lastRunId = summary.id;
    });
  }

  // --- attestations, decisions, human review ---------------------------------------------------------------------

  addAttestation(projectId: string, input: Omit<Attestation, 'id' | 'attestedAt'>, now: Date = new Date()): Attestation {
    const attestation = AttestationSchema.parse({ ...input, id: newAttestationId(), attestedAt: now.toISOString() });
    this.update(projectId, (project) => {
      // One attestation per requirement: a newer answer replaces the older one.
      project.attestations = [...project.attestations.filter((a) => a.requirementId !== attestation.requirementId), attestation];
    });
    return attestation;
  }

  removeAttestation(projectId: string, attestationId: string): boolean {
    let removed = false;
    this.update(projectId, (project) => {
      const before = project.attestations.length;
      project.attestations = project.attestations.filter((a) => a.id !== attestationId);
      removed = project.attestations.length !== before;
    });
    return removed;
  }

  setFindingDecision(projectId: string, decision: FindingDecision | { fingerprint: string; status: 'open' }): Project {
    return this.update(projectId, (project) => {
      project.findingDecisions = project.findingDecisions.filter((d) => d.fingerprint !== decision.fingerprint);
      if (decision.status !== 'open') project.findingDecisions.push(decision);
    });
  }

  setHumanCodeReview(projectId: string, review: HumanCodeReview): Project {
    return this.update(projectId, (project) => {
      project.humanCodeReview = review;
    });
  }
}

export function toListItem(project: Project): ProjectListItem {
  return {
    id: project.id,
    name: project.name,
    createdAt: project.createdAt,
    updatedAt: project.updatedAt,
    status: project.status,
    wizardStep: project.wizardStep,
    ...(project.lastRunId ? { lastRunId: project.lastRunId } : {}),
    designStale: project.designStale,
    buildStale: project.buildStale,
    ...(project.archivedAt ? { archivedAt: project.archivedAt } : {}),
    ...(project.origin ? { origin: project.origin } : {}),
  };
}
