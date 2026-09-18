/**
 * `securevibe.provenance.json` (AISVS Appendix C AC.7.1/AC.10.1 — shared/src/pipeline.ts `ProvenanceSchema`).
 *
 * Built up in three passes as the pipeline runs:
 *  1. `initialProvenance` right after scaffold — every template file is `origin: "template"`.
 *  2. `markGeneratedFiles` after `generate`/`fix` — files the agent touched become `ai-generated` / `ai-fixed`.
 *  3. `finalizeProvenance` at the `reports` stage — framework/tool versions, the code-tree hash and the
 *     human-involvement summary are filled in from what the whole run observed.
 */
import { createHash } from 'node:crypto';
import type { GeneratedFileOrigin, Provenance, RecipeApplication, RunMode } from '@shared/pipeline.js';
import { contentSha256File, listFiles, sha256File } from './files.js';

export interface InitialProvenanceInput {
  runId: string;
  projectId: string;
  mode: RunMode;
  appDir: string;
  templateVersion: string;
  securevibeVersion: string;
  designProfileHash: string;
  designHash: string;
  protectedFileHashes: Record<string, string>;
  /** Hash of the template's files (generator/template-hash.ts): a newer template means an update is available. */
  templateHash?: string;
  sandbox: { mode: string; note: string };
  previousRunId?: string;
  contractHash?: string;
  generatedAt?: string;
}

const REPORT_SCHEMA_VERSION = '1.0.0';

export function initialProvenance(input: InitialProvenanceInput): Provenance {
  const generatedFiles = listFiles(input.appDir).map((f) => {
    const sha256 = sha256File(f.absPath) ?? '';
    const contentSha256 = contentSha256File(f.absPath);
    return { path: f.relPath, sha256, ...(contentSha256 ? { contentSha256 } : {}), origin: 'template' as GeneratedFileOrigin };
  });
  return {
    reportSchemaVersion: REPORT_SCHEMA_VERSION,
    tool: `SecureVibe ${input.securevibeVersion}`,
    securevibeVersion: input.securevibeVersion,
    templateVersion: input.templateVersion,
    frameworkVersions: { asvs: '', aisvs: '', sbd: '' },
    toolVersions: {},
    runId: input.runId,
    ...(input.previousRunId ? { previousRunId: input.previousRunId } : {}),
    projectId: input.projectId,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    mode: input.mode,
    humanInvolvement: { summary: 'The build has not been approved yet.', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
    designProfileHash: input.designProfileHash,
    designHash: input.designHash,
    ...(input.contractHash ? { contractHash: input.contractHash } : {}),
    codeTreeHash: '',
    generatedFiles,
    recipes: [],
    protectedFileHashes: input.protectedFileHashes,
    ...(input.templateHash ? { templateHash: input.templateHash } : {}),
    sandbox: input.sandbox,
  };
}

/**
 * Marks files the generation/fix agent touched. A file that already existed keeps its earlier `firstSeenRun`
 * intent by simply being replaced (provenance only tracks the current state, not history across files).
 */
export function markGeneratedFiles(
  provenance: Provenance,
  appDir: string,
  touchedRelPaths: string[],
  origin: Extract<GeneratedFileOrigin, 'ai-generated' | 'ai-fixed' | 'expanded'>,
  opts: { correlationId?: string; promptHash?: string; fixRound?: number } = {},
): Provenance {
  const byPath = new Map(provenance.generatedFiles.map((f) => [f.path, f]));
  for (const rel of touchedRelPaths) {
    const abs = `${appDir}/${rel}`;
    const sha256 = sha256File(abs);
    if (sha256 === undefined) {
      // The file was deleted by the agent; drop it from the manifest.
      byPath.delete(rel);
      continue;
    }
    const contentSha256 = contentSha256File(abs);
    byPath.set(rel, {
      path: rel,
      sha256,
      ...(contentSha256 ? { contentSha256 } : {}),
      origin,
      ...(opts.correlationId ? { correlationId: opts.correlationId } : {}),
      ...(opts.promptHash ? { promptHash: opts.promptHash } : {}),
      ...(opts.fixRound !== undefined ? { fixRound: opts.fixRound } : {}),
    });
  }
  return { ...provenance, generatedFiles: [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path)) };
}

/**
 * Records what the recipe library built (generator/recipes): the applications themselves, and, on every file a
 * recipe wrote, which recipe and which version of it produced the file. That is what lets a later build, a
 * template upgrade and the version diff say where a file came from without guessing from its contents.
 */
export function recordRecipes(provenance: Provenance, appDir: string, applications: RecipeApplication[]): Provenance {
  const byPath = new Map<string, { id: string; version: string; instance: string }>();
  for (const app of applications) {
    for (const path of app.files) byPath.set(path, { id: app.recipeId, version: app.recipeVersion, instance: app.instance });
  }
  const withRecipes = markGeneratedFiles(provenance, appDir, [...byPath.keys()], 'expanded');
  return {
    ...withRecipes,
    recipes: [...provenance.recipes.filter((r) => !applications.some((a) => a.recipeId === r.recipeId && a.instance === r.instance)), ...applications],
    generatedFiles: withRecipes.generatedFiles.map((f) => {
      const recipe = byPath.get(f.path);
      return recipe ? { ...f, recipe } : f;
    }),
  };
}

export interface FinalizeProvenanceInput {
  frameworkVersions: { asvs: string; aisvs: string; sbd: string };
  toolVersions: Record<string, string>;
  vulnDbAsOf?: string;
  llm?: Provenance['llm'];
  humanInvolvement: Provenance['humanInvolvement'];
  appDir: string;
  protectedFileHashes: Record<string, string>;
}

/** Recomputes the whole-tree hash and fills in the fields only known once the run is complete. */
export function finalizeProvenance(provenance: Provenance, input: FinalizeProvenanceInput): Provenance {
  const files = listFiles(input.appDir)
    .map((f) => ({ path: f.relPath, sha256: sha256File(f.absPath) ?? '' }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const codeTreeHash = hashOfList(files);
  return {
    ...provenance,
    frameworkVersions: input.frameworkVersions,
    toolVersions: input.toolVersions,
    ...(input.vulnDbAsOf ? { vulnDbAsOf: input.vulnDbAsOf } : {}),
    ...(input.llm ? { llm: input.llm } : {}),
    humanInvolvement: input.humanInvolvement,
    codeTreeHash,
    protectedFileHashes: input.protectedFileHashes,
  };
}

function hashOfList(files: { path: string; sha256: string }[]): string {
  const h = createHash('sha256');
  for (const f of files) h.update(`${f.path}:${f.sha256}\n`);
  return h.digest('hex');
}
