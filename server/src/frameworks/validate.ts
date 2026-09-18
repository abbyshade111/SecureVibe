/**
 * Referenced-id validation: every ASVS / AISVS / Appendix C / SbD id mentioned in the knowledge base, the template
 * manifest and the scanner/compliance sources must exist in data/frameworks. Used by server/tests/contracts.test.ts
 * and runnable on its own: `tsx server/src/frameworks/validate.ts`.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadFrameworks, REPO_ROOT, standardForId, type Frameworks } from './load.js';

/** Matches requirement ids (V6.2.1, C2.1.3, AC.4.1) and SbD control ids (AS-01) inside free text. */
export const ID_PATTERN = /\bV\d+\.\d+\.\d+\b|\bC\d+\.\d+\.\d+\b|\bAC\.\d+\.\d+\b|\b(?:AS|DM|RR|AC|MT)-\d\d\b/g;

export function extractReferencedIds(text: string): string[] {
  return [...new Set(text.match(ID_PATTERN) ?? [])];
}

export interface IdValidation {
  known: string[];
  unknown: string[];
}

/** Splits ids into those that exist in the frameworks and those that do not. Chapter/section ids count as known. */
export function validateReferencedIds(refs: string[], frameworks: Frameworks = loadFrameworks()): IdValidation {
  const known: string[] = [];
  const unknown: string[] = [];
  for (const id of new Set(refs)) {
    const exists = standardForId(id) === 'sbd' ? frameworks.getSbdControl(id) !== undefined : frameworks.hasScope(id);
    (exists ? known : unknown).push(id);
  }
  return { known, unknown };
}

export interface FileReferences {
  file: string; // repo-relative
  ids: string[];
}

export interface ReferenceScan {
  files: FileReferences[];
  /** Locations that do not exist yet (another module has not written them). */
  skipped: string[];
}

const SCAN_EXTENSIONS = ['.ts', '.json'];

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry.startsWith('.')) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, out);
    else if (SCAN_EXTENSIONS.some((ext) => entry.endsWith(ext))) out.push(full);
  }
}

/** The locations the contracts test scans, relative to the repo root. */
export const REFERENCE_LOCATIONS = [
  'data/knowledge',
  'templates/secure-web-app/securevibe.manifest.json',
  'server/src/scanners',
  'server/src/compliance',
] as const;

export function scanReferencedIds(repoRoot: string = REPO_ROOT): ReferenceScan {
  const files: FileReferences[] = [];
  const skipped: string[] = [];
  for (const location of REFERENCE_LOCATIONS) {
    const full = join(repoRoot, location);
    if (!existsSync(full)) {
      skipped.push(location);
      continue;
    }
    const paths: string[] = [];
    if (statSync(full).isDirectory()) walk(full, paths);
    else paths.push(full);
    for (const p of paths) {
      const ids = extractReferencedIds(readFileSync(p, 'utf8'));
      if (ids.length > 0) files.push({ file: relative(repoRoot, p), ids });
    }
  }
  return { files, skipped };
}

export interface ReferenceCheck {
  ok: boolean;
  skipped: string[];
  problems: { file: string; unknown: string[] }[];
  scannedFiles: number;
  referencedIds: number;
}

export function checkReferencedIds(repoRoot: string = REPO_ROOT, frameworks: Frameworks = loadFrameworks()): ReferenceCheck {
  const scan = scanReferencedIds(repoRoot);
  const problems: ReferenceCheck['problems'] = [];
  const all = new Set<string>();
  for (const f of scan.files) {
    for (const id of f.ids) all.add(id);
    const { unknown } = validateReferencedIds(f.ids, frameworks);
    if (unknown.length > 0) problems.push({ file: f.file, unknown });
  }
  return {
    ok: problems.length === 0,
    skipped: scan.skipped,
    problems,
    scannedFiles: scan.files.length,
    referencedIds: all.size,
  };
}

function main(): void {
  const result = checkReferencedIds();
  for (const s of result.skipped) process.stdout.write(`skipped (not written yet): ${s}\n`);
  for (const p of result.problems) process.stdout.write(`UNKNOWN ids in ${p.file}: ${p.unknown.join(', ')}\n`);
  process.stdout.write(
    `${result.scannedFiles} files, ${result.referencedIds} distinct ids, ${result.problems.length} files with unknown ids\n`,
  );
  process.exitCode = result.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
