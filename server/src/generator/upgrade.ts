/**
 * "Update to the latest template" for an app that was built earlier (docs/CONTRACTS.md "Template upgrades").
 *
 * The template improves over time (fixes, new checks, new tests). A rebuild would apply all of that but writes
 * the app again with AI, which costs money and can change features. An upgrade instead:
 *
 *  1. stages the current template for the app's design (the same way a build starts), next to the app;
 *  2. compares the three views of every file — what the old template gave the app (recorded in the app's
 *     provenance), what the app has now, and what the new template has;
 *  3. replaces template files the app never changed, adds files the template gained, removes unchanged files
 *     the template dropped, and leaves alone every file that carries the owner's or Claude's changes, listing them;
 *  4. adds new settings keys to the app's .env without touching existing values, refreshes the packages when the
 *     lockfile changed, and rewrites the provenance.
 *
 * The decision itself (`planUpgrade`) is a pure function, so the rules are tested without building anything.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { cp, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { BuildSpec } from '@shared/design.js';
import { ProvenanceSchema, type GeneratedFileOrigin, type Provenance } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import type { TemplateUpgrade } from '@shared/project.js';
import type { Settings } from '../config.js';
import { DEFAULT_WALK_IGNORE, listFiles, sha256File } from './files.js';
import { initialProvenance } from './provenance.js';
import { computeProtectedFileHashes, stageTemplate, tryNodeModulesFastPath } from './scaffold.js';
import { templateHash } from './template-hash.js';

/** Files an upgrade never writes or removes: the app's own secrets, data, certificate and packages. */
const NEVER_TOUCH = /^(\.env$|securevibe\.provenance\.json$|FIRST-LOGIN\.txt$|data\/|certs\/|node_modules\/|tmp\/|home\/)/;

export interface OldEntry {
  sha256: string;
  origin: GeneratedFileOrigin;
}

export interface UpgradePlan {
  /** Files taken from the new template because the app's copy was the old template's, unchanged. */
  updated: string[];
  /** Files the new template has and the app does not. */
  added: string[];
  /** Files the old template gave the app, unchanged since, that the new template no longer has. */
  removed: string[];
  /** Template files with the owner's or Claude's changes (or from a source the provenance does not know): kept as they are. */
  kept: string[];
  unchanged: number;
}

export function planUpgrade(input: { oldEntries: Map<string, OldEntry>; appHashes: Map<string, string>; newHashes: Map<string, string> }): UpgradePlan {
  const plan: UpgradePlan = { updated: [], added: [], removed: [], kept: [], unchanged: 0 };
  for (const [path, newSha] of input.newHashes) {
    if (NEVER_TOUCH.test(path)) continue;
    const appSha = input.appHashes.get(path);
    if (appSha === undefined) {
      plan.added.push(path);
      continue;
    }
    if (appSha === newSha) {
      plan.unchanged += 1;
      continue;
    }
    const old = input.oldEntries.get(path);
    if (old && old.origin === 'template' && old.sha256 === appSha) plan.updated.push(path);
    else plan.kept.push(path);
  }
  for (const [path, old] of input.oldEntries) {
    if (NEVER_TOUCH.test(path) || input.newHashes.has(path)) continue;
    if (old.origin !== 'template') continue;
    const appSha = input.appHashes.get(path);
    if (appSha !== undefined && appSha === old.sha256) plan.removed.push(path);
  }
  for (const list of [plan.updated, plan.added, plan.removed, plan.kept]) list.sort();
  return plan;
}

/** Appends keys the new template's .env has and the app's .env lacks; existing lines are never changed. */
export function mergeEnvKeys(appEnv: string, templateEnv: string): { text: string; added: string[] } {
  const present = new Set<string>();
  for (const line of appEnv.split(/\r?\n/)) {
    const m = /^\s*([A-Z][A-Z0-9_]*)\s*=/.exec(line);
    if (m) present.add(m[1]!);
  }
  const added: string[] = [];
  const lines: string[] = [];
  for (const line of templateEnv.split(/\r?\n/)) {
    const m = /^\s*([A-Z][A-Z0-9_]*)\s*=(.*)$/.exec(line);
    if (!m || present.has(m[1]!)) continue;
    present.add(m[1]!);
    added.push(m[1]!);
    lines.push(`${m[1]}=${m[2]!.trim()}`);
  }
  if (added.length === 0) return { text: appEnv, added };
  const base = appEnv.replace(/\n*$/, '\n');
  return { text: `${base}\n# Added by SecureVibe's template update\n${lines.join('\n')}\n`, added };
}

function hashesOf(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const f of listFiles(dir, DEFAULT_WALK_IGNORE)) {
    const sha = sha256File(f.absPath);
    if (sha !== undefined) out.set(f.relPath, sha);
  }
  return out;
}

function readOldProvenance(appDir: string): Provenance | undefined {
  const file = join(appDir, 'securevibe.provenance.json');
  if (!existsSync(file)) return undefined;
  try {
    const parsed = ProvenanceSchema.safeParse(JSON.parse(readFileSync(file, 'utf8')));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

export interface UpgradeInput {
  templateDir: string;
  projectDir: string;
  appDir: string;
  projectId: string;
  profile: DesignProfile;
  buildSpec: BuildSpec;
  settings: Settings;
  knowledgeDir: string;
  securevibeVersion: string;
  designProfileHash: string;
  designHash: string;
  log(msg: string): void;
}

export async function upgradeApp(input: UpgradeInput): Promise<TemplateUpgrade> {
  const { appDir, templateDir, log } = input;
  const stageDir = join(input.projectDir, 'app.upgrade');
  await rm(stageDir, { recursive: true, force: true });
  const warnings: string[] = [];
  try {
    const staged = await stageTemplate({
      templateDir,
      targetDir: stageDir,
      profile: input.profile,
      buildSpec: input.buildSpec,
      settings: input.settings,
      knowledgeDir: input.knowledgeDir,
      log,
    });
    warnings.push(...staged.warnings);

    log('Comparing the app with the latest template…');
    const old = readOldProvenance(appDir);
    const oldEntries = new Map<string, OldEntry>((old?.generatedFiles ?? []).map((f) => [f.path, { sha256: f.sha256, origin: f.origin }]));
    const plan = planUpgrade({ oldEntries, appHashes: hashesOf(appDir), newHashes: hashesOf(stageDir) });

    log(`Applying the update: ${plan.updated.length} file(s) updated, ${plan.added.length} added, ${plan.removed.length} removed, ${plan.kept.length} kept with your changes.`);
    for (const rel of [...plan.updated, ...plan.added]) {
      mkdirSync(dirname(join(appDir, rel)), { recursive: true });
      await cp(join(stageDir, rel), join(appDir, rel), { force: true });
    }
    for (const rel of plan.removed) rmSync(join(appDir, rel), { force: true });

    // New settings the template introduced get their default; the app's own values stay exactly as they are.
    let envKeysAdded: string[] = [];
    const appEnvFile = join(appDir, '.env');
    const stagedEnvFile = join(stageDir, '.env');
    if (existsSync(appEnvFile) && existsSync(stagedEnvFile)) {
      const merged = mergeEnvKeys(readFileSync(appEnvFile, 'utf8'), readFileSync(stagedEnvFile, 'utf8'));
      if (merged.added.length) {
        writeFileSync(appEnvFile, merged.text, { mode: 0o600 });
        envKeysAdded = merged.added;
      }
    }

    // A changed lockfile means the installed packages no longer match; the template's tested set replaces them
    // when it can, otherwise the next check installs them.
    const changed = new Set([...plan.updated, ...plan.added]);
    if (changed.has('package-lock.json') || changed.has('package.json')) {
      log('Refreshing the installed packages…');
      rmSync(join(appDir, 'node_modules'), { recursive: true, force: true });
      const reused = await tryNodeModulesFastPath(templateDir, appDir);
      if (!reused) warnings.push('The packages changed with this update and will be installed at the start of the next check.');
    }

    // Provenance: every file now in the app, with template files at their new hashes and everything else as it was.
    const version = staged.manifest.version;
    const hash = templateHash(templateDir);
    const base: Provenance =
      old ??
      initialProvenance({
        runId: `upgrade-${Date.now().toString(36)}`,
        projectId: input.projectId,
        mode: 'full',
        appDir,
        templateVersion: version,
        securevibeVersion: input.securevibeVersion,
        designProfileHash: input.designProfileHash,
        designHash: input.designHash,
        protectedFileHashes: {},
        sandbox: { mode: 'node-permission-model', note: "Generated code runs under Node's permission model with the file system restricted to the project folder; network access is not restricted." },
      });
    const generatedFiles = [...hashesOf(appDir)].map(([path, sha256]) => {
      const previous = oldEntries.get(path);
      const origin: GeneratedFileOrigin = changed.has(path) ? 'template' : (previous?.origin ?? 'template');
      return { path, sha256, origin };
    });
    const provenance: Provenance = {
      ...base,
      templateVersion: version,
      templateHash: hash,
      generatedFiles,
      protectedFileHashes: computeProtectedFileHashes(appDir, staged.manifest),
    };
    writeFileSync(join(appDir, 'securevibe.provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);

    return {
      at: new Date().toISOString(),
      templateVersion: version,
      templateHash: hash,
      updated: plan.updated,
      added: plan.added,
      removed: plan.removed,
      kept: plan.kept,
      envKeysAdded,
      warnings,
    };
  } finally {
    await rm(stageDir, { recursive: true, force: true });
  }
}
