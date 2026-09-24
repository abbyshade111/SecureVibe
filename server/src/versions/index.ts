/**
 * App versions and what changed between them (docs/CONTRACTS.md "Version diff").
 *
 * Every rebuild keeps the previous app as `app-v<N>/`, and every version carries `securevibe.provenance.json`
 * (which run built it, and where each file came from). A diff lists the files that differ between two versions,
 * with the origin of each (template, expanded from the answers, written or fixed by Claude, the owner's), and how
 * the checks came out for each version's run: problems found or resolved, verified coverage, tests.
 *
 * Settings files (.env) are never shown — they hold secrets — only the fact that they changed.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { AppFileResponse, AppVersion, DiffFile, FileDiffResponse, VersionDiff } from '@shared/api.js';
import { isOpen, type Finding } from '@shared/findings.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { DEFAULT_WALK_IGNORE, listFiles, sha256File } from '../generator/files.js';
import { confinePath, type ProjectStore } from '../store/index.js';
import { countChanges, unifiedDiff } from './line-diff.js';

const SECRET_FILES = /^(\.env|\.env\..*|FIRST-LOGIN\.txt)$/;
const IGNORE = [...DEFAULT_WALK_IGNORE, 'securevibe.provenance.json', 'package-lock.json'];
/** Files above this size are compared by hash only. */
const MAX_TEXT_BYTES = 400_000;
const MAX_FILES = 300;

interface ProvenanceLite {
  runId?: string;
  generatedAt?: string;
  templateVersion?: string;
  generatedFiles?: { path: string; origin: string }[];
}

function readProvenance(dir: string): ProvenanceLite | undefined {
  const file = join(dir, 'securevibe.provenance.json');
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as ProvenanceLite;
  } catch {
    return undefined;
  }
}

export class VersionNotFoundError extends Error {
  constructor(readonly versionId: string) {
    super(`There is no version "${versionId}" of this app.`);
    this.name = 'VersionNotFoundError';
  }
}

export function versionDir(store: ProjectStore, projectId: string, versionId: string): string {
  const { dir, appDir } = store.paths(projectId);
  if (versionId === 'current') return appDir;
  const m = /^v(\d{1,4})$/.exec(versionId);
  if (!m) throw new VersionNotFoundError(versionId);
  return join(dir, `app-v${m[1]}`);
}

function describe(store: ProjectStore, projectId: string, id: string, dir: string, currentRunId?: string): AppVersion {
  const prov = readProvenance(dir);
  const runId = id === 'current' ? (currentRunId ?? prov?.runId) : prov?.runId;
  const run = runId ? store.readRun(projectId, runId) : undefined;
  const builtAt = run?.finishedAt ?? run?.startedAt ?? prov?.generatedAt;
  const n = id === 'current' ? undefined : id.slice(1);
  const label = id === 'current' ? 'Current version' : `Version ${n}`;
  return {
    id,
    label,
    ...(runId ? { runId } : {}),
    ...(builtAt ? { builtAt } : {}),
    ...(prov?.templateVersion ? { templateVersion: prov.templateVersion } : {}),
  };
}

/** The current app first, then archived versions, newest first. Only versions that exist on disk are listed. */
export function listVersions(store: ProjectStore, projectId: string): AppVersion[] {
  const project = store.mustGet(projectId);
  const { dir, appDir } = store.paths(projectId);
  const out: AppVersion[] = [];
  if (existsSync(appDir)) out.push(describe(store, projectId, 'current', appDir, project.lastRunId));
  const archived = readdirSync(dir)
    .map((name) => /^app-v(\d+)$/.exec(name))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => Number(m[1]))
    .filter((n) => statSync(join(dir, `app-v${n}`)).isDirectory())
    .sort((a, b) => b - a);
  for (const n of archived) out.push(describe(store, projectId, `v${n}`, join(dir, `app-v${n}`)));
  return out;
}

function isBinary(buf: Buffer): boolean {
  const sample = buf.subarray(0, 8000);
  return sample.includes(0);
}

function readText(file: string): { text?: string; binary: boolean; tooLarge: boolean } {
  const size = statSync(file).size;
  if (size > MAX_TEXT_BYTES) return { binary: false, tooLarge: true };
  const buf = readFileSync(file);
  if (isBinary(buf)) return { binary: true, tooLarge: false };
  return { text: buf.toString('utf8'), binary: false, tooLarge: false };
}

function brief(f: Finding) {
  // The file goes with it: several findings of one rule share a title, and without the location a comparison
  // shows the same sentence repeated with nothing to tell the instances apart.
  return {
    id: f.id,
    fingerprint: f.fingerprint,
    severity: f.severity,
    ruleId: f.ruleId,
    title: f.title,
    ...(f.location?.file ? { file: f.location.file } : {}),
  };
}

function percent(run: PipelineRun | undefined, standard: 'asvs' | 'aisvs'): number | undefined {
  const s = standard === 'asvs' ? run?.compliance?.asvs : run?.compliance?.aisvs;
  return s ? Math.round(s.summary.verifiedPassPercent * 10) / 10 : undefined;
}

function testCounts(run: PipelineRun | undefined): { total: number; passed: number; failed: number; skipped: number } | undefined {
  const details = run?.stages.find((s) => s.id === 'unit-tests')?.details as { total?: number; passed?: number; failed?: number; skipped?: number } | undefined;
  return details && typeof details.total === 'number'
    ? { total: details.total, passed: details.passed ?? 0, failed: details.failed ?? 0, skipped: details.skipped ?? 0 }
    : undefined;
}

function resultsDelta(store: ProjectStore, projectId: string, from: AppVersion, to: AppVersion): VersionDiff['results'] {
  const before = from.runId ? store.readRun(projectId, from.runId) : undefined;
  const after = to.runId ? store.readRun(projectId, to.runId) : undefined;
  if (!before || !after) return undefined;
  const openBefore = new Map(before.findings.filter(isOpen).map((f) => [f.fingerprint, f]));
  const openAfter = new Map(after.findings.filter(isOpen).map((f) => [f.fingerprint, f]));
  const findingsNew = [...openAfter.values()].filter((f) => !openBefore.has(f.fingerprint)).map(brief);
  const findingsResolved = [...openBefore.values()].filter((f) => !openAfter.has(f.fingerprint)).map(brief);
  const findingsStillOpen = [...openAfter.keys()].filter((fp) => openBefore.has(fp)).length;
  const asvsB = percent(before, 'asvs');
  const asvsA = percent(after, 'asvs');
  const aisvsB = percent(before, 'aisvs');
  const aisvsA = percent(after, 'aisvs');
  const tB = testCounts(before);
  const tA = testCounts(after);
  return {
    findingsNew,
    findingsResolved,
    findingsStillOpen,
    ...(asvsB !== undefined && asvsA !== undefined ? { asvs: { before: asvsB, after: asvsA } } : {}),
    ...(aisvsB !== undefined && aisvsA !== undefined ? { aisvs: { before: aisvsB, after: aisvsA } } : {}),
    ...(tB && tA ? { tests: { before: tB, after: tA } } : {}),
  };
}

export function diffVersions(store: ProjectStore, projectId: string, fromId: string, toId: string): VersionDiff {
  const versions = listVersions(store, projectId);
  const from = versions.find((v) => v.id === fromId);
  const to = versions.find((v) => v.id === toId);
  if (!from) throw new VersionNotFoundError(fromId);
  if (!to) throw new VersionNotFoundError(toId);
  const fromDir = versionDir(store, projectId, fromId);
  const toDir = versionDir(store, projectId, toId);
  const fromFiles = new Map(listFiles(fromDir, IGNORE).map((f) => [f.relPath, f.absPath]));
  const toFiles = new Map(listFiles(toDir, IGNORE).map((f) => [f.relPath, f.absPath]));
  const originsTo = new Map((readProvenance(toDir)?.generatedFiles ?? []).map((f) => [f.path, f.origin]));
  const originsFrom = new Map((readProvenance(fromDir)?.generatedFiles ?? []).map((f) => [f.path, f.origin]));

  const files: DiffFile[] = [];
  const paths = [...new Set([...fromFiles.keys(), ...toFiles.keys()])].sort();
  let truncated = false;
  for (const path of paths) {
    if (files.length >= MAX_FILES) {
      truncated = true;
      break;
    }
    const a = fromFiles.get(path);
    const b = toFiles.get(path);
    const secret = SECRET_FILES.test(path);
    const origin = originsTo.get(path) ?? originsFrom.get(path);
    const base = { path, ...(origin ? { origin } : {}), secret, binary: false, linesAdded: 0, linesRemoved: 0 };
    if (a && !b) {
      files.push({ ...base, kind: 'removed' });
      continue;
    }
    if (!a && b) {
      files.push({ ...base, kind: 'added' });
      continue;
    }
    if (!a || !b) continue;
    if (sha256File(a) === sha256File(b)) continue;
    if (secret) {
      files.push({ ...base, kind: 'changed' });
      continue;
    }
    const ta = readText(a);
    const tb = readText(b);
    if (ta.binary || tb.binary || ta.tooLarge || tb.tooLarge || ta.text === undefined || tb.text === undefined) {
      files.push({ ...base, kind: 'changed', binary: true });
      continue;
    }
    const counts = countChanges(ta.text, tb.text);
    files.push({ ...base, kind: 'changed', linesAdded: counts.linesAdded, linesRemoved: counts.linesRemoved });
  }
  return { from, to, files, truncated, results: resultsDelta(store, projectId, from, to) };
}

export function fileDiff(store: ProjectStore, projectId: string, fromId: string, toId: string, relPath: string): FileDiffResponse {
  if (SECRET_FILES.test(relPath)) return { path: relPath, kind: 'changed', unified: 'This file holds secrets, so its contents are not shown.\n', truncated: false };
  const fromDir = versionDir(store, projectId, fromId);
  const toDir = versionDir(store, projectId, toId);
  const a = confinePath(fromDir, relPath);
  const b = confinePath(toDir, relPath);
  const hasA = existsSync(a) && statSync(a).isFile();
  const hasB = existsSync(b) && statSync(b).isFile();
  if (!hasA && !hasB) throw new VersionNotFoundError(relPath);
  const ta = hasA ? readText(a) : { text: '', binary: false, tooLarge: false };
  const tb = hasB ? readText(b) : { text: '', binary: false, tooLarge: false };
  const kind: FileDiffResponse['kind'] = !hasA ? 'added' : !hasB ? 'removed' : 'changed';
  if (ta.binary || tb.binary) return { path: relPath, kind, unified: 'This is not a text file, so its contents are not shown.\n', truncated: false };
  if (ta.tooLarge || tb.tooLarge) return { path: relPath, kind, unified: 'This file is too large to compare line by line.\n', truncated: true };
  const d = unifiedDiff(ta.text ?? '', tb.text ?? '', relPath);
  return { path: relPath, kind, unified: d.text, truncated: d.truncated };
}

/** Above this many lines only the beginning of a file is sent; the viewer says so and offers the whole file. */
const MAX_VIEW_LINES = 3000;

/**
 * One file of the generated app, for the "show me this code" link on a finding (docs/CONTRACTS.md "Reading the
 * app's code").
 *
 * Read-only and confined to that version's folder by `confinePath`. The same rules as the diff apply: settings
 * files are never sent (they hold secrets), binaries and very large files are described instead of shown. Unlike
 * the diff, which only ever compares the app's own root files, this checks the file's own name as well, so a
 * `.env` in a sub-folder is held back too.
 */
export function readAppFile(store: ProjectStore, projectId: string, versionId: string, relPath: string): AppFileResponse {
  const dir = versionDir(store, projectId, versionId);
  const base = { path: relPath, version: versionId, appDir: dir, text: '', lineCount: 0, truncated: false };
  if (SECRET_FILES.test(relPath) || SECRET_FILES.test(relPath.split('/').pop() ?? '')) {
    return { ...base, notShown: 'This file holds passwords and keys, so SecureVibe never shows it. Open it yourself in your app folder if you need to.' };
  }
  const file = confinePath(dir, relPath);
  if (!existsSync(file) || !statSync(file).isFile()) throw new VersionNotFoundError(relPath);

  const origin = (readProvenance(dir)?.generatedFiles ?? []).find((f) => f.path === relPath)?.origin;
  const withOrigin = { ...base, ...(origin ? { origin } : {}) };

  const read = readText(file);
  if (read.binary) return { ...withOrigin, notShown: 'This is not a text file (an image, for example), so there is nothing to read here.' };
  if (read.tooLarge || read.text === undefined) {
    return { ...withOrigin, notShown: 'This file is too big to show here. Open it in your app folder instead.' };
  }
  const lines = read.text.split('\n');
  const truncated = lines.length > MAX_VIEW_LINES;
  return {
    ...withOrigin,
    text: truncated ? lines.slice(0, MAX_VIEW_LINES).join('\n') : read.text,
    lineCount: lines.length,
    truncated,
  };
}
