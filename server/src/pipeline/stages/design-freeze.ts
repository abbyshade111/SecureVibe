/**
 * `design-freeze` (SbD step 8): validates the profile is complete, derives the design one last time, computes the
 * security-contract hash the generation agent's prompt is pinned to, and writes `design/*` to the project folder.
 * Skipped in `verify-only` mode, which reads the already-frozen design back from the project instead.
 */
import { DesignProfileSchema } from '@shared/profile.js';
import { ProvenanceSchema, type StageResult } from '@shared/pipeline.js';
import { canonicalJson, deriveDesign, promptLibraryHash, renderDesignMarkdown, sha256Hex } from '../../integration.js';
import { writeJsonAtomic } from '../../store/index.js';
import { finishStage, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';

export async function runDesignFreeze(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'design-freeze');

  const parsed = DesignProfileSchema.safeParse(ctx.project.profile);
  if (!parsed.success) {
    return finishStage(ctx, 'design-freeze', 'failed', 'Your design is not complete yet. Go back to the wizard and answer the remaining questions.', started, {
      details: { issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
    });
  }
  const profile = parsed.data;
  ctx.profile = profile;

  const design = deriveDesign(profile, {
    knowledge: ctx.knowledge,
    frameworks: ctx.frameworks,
    ...(ctx.project.attestations ? { attestations: ctx.project.attestations } : {}),
    ...(ctx.project.design ? { previous: ctx.project.design } : {}),
    ...(ctx.project.escalationAcknowledgedAt ? { escalationAcknowledgedAt: ctx.project.escalationAcknowledgedAt } : {}),
  });

  if (!design.contractHash) {
    design.contractHash = sha256Hex(`${canonicalJson(design.securityContract)}:${promptLibraryHash()}`);
  }
  ctx.design = design;
  ctx.buildSpec = design.buildSpec;

  await mkdir(ctx.paths.designDir, { recursive: true });
  const rendered = renderDesignMarkdown(design, profile);
  await writeFile(join(ctx.paths.designDir, 'design.md'), rendered['design.md']);
  await writeFile(join(ctx.paths.designDir, 'security-contract.md'), rendered['security-contract.md']);
  await writeFile(join(ctx.paths.designDir, 'threat-model.md'), rendered['threat-model.md']);
  await writeFile(join(ctx.paths.designDir, 'diagram.mmd'), rendered['diagram.mmd']);
  const adrDir = join(ctx.paths.designDir, 'adr');
  await mkdir(adrDir, { recursive: true });
  for (const [file, content] of Object.entries(rendered.adrs)) await writeFile(join(adrDir, file), content);
  await writeJsonAtomic(join(ctx.paths.designDir, 'design.json'), design);

  ctx.project.design = design;
  ctx.project.profileHash = design.profileHash;
  ctx.project.status = 'designed';
  ctx.store.save(ctx.project);

  return finishStage(ctx, 'design-freeze', 'passed', 'The design documents and the security contract for the code generator are written.', started);
}

/** verify-only mode: read the already-frozen design back instead of deriving it again. */
export function loadFrozenDesign(ctx: PipelineCtx): StageResult {
  const started = startStage(ctx, 'design-freeze');
  if (!ctx.project.design) {
    return finishStage(ctx, 'design-freeze', 'failed', 'This project has no design yet, so it cannot be verified.', started);
  }
  ctx.design = ctx.project.design;
  ctx.buildSpec = ctx.project.design.buildSpec;
  if (DesignProfileSchema.safeParse(ctx.project.profile).success) {
    ctx.profile = DesignProfileSchema.parse(ctx.project.profile);
  }
  // The provenance written by the build tells the checks which files are protected and what they should hash to.
  const provenanceFile = join(ctx.appDir, 'securevibe.provenance.json');
  if (!ctx.provenance && existsSync(provenanceFile)) {
    try {
      ctx.provenance = ProvenanceSchema.parse(JSON.parse(readFileSync(provenanceFile, 'utf8')));
    } catch {
      ctx.log('design-freeze', 'securevibe.provenance.json could not be read; the integrity checks will report it.');
    }
  }
  return finishStage(ctx, 'design-freeze', 'skipped', 'Using the design already on file (verify-only run).', started, {
    skippedReason: existsSync(ctx.appDir) ? 'verify-only run (the design on file was used)' : 'verify-only run (the application folder does not exist yet)',
  });
}
