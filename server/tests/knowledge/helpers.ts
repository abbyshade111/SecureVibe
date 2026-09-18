/**
 * Shared helpers for the knowledge-base tests: paths, JSON loading and the set of framework ids.
 * The framework files are read directly (not through server/src/frameworks) so these tests only depend on data.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const KNOWLEDGE_DIR = join(REPO_ROOT, 'data', 'knowledge');
export const FRAMEWORKS_DIR = join(REPO_ROOT, 'data', 'frameworks');

export function readJson<T = unknown>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}

export function readKnowledge<T = unknown>(name: string): T {
  return readJson<T>(join(KNOWLEDGE_DIR, name));
}

interface FrameworkRequirement {
  id: string;
  description: string;
  level: number;
}
interface ChapterFramework {
  chapters: Array<{ id: string; name: string; sections: Array<{ id: string; name: string; requirements: FrameworkRequirement[] }> }>;
}
interface AppendixC {
  families: Array<{ id: string; name: string; requirements: FrameworkRequirement[] }>;
}
interface SbdChecklist {
  checklistDomains: Array<{ id: string; name: string; controls: Array<{ id: string; statement: string }> }>;
}

export interface FrameworkIds {
  /** Every ASVS, AISVS and Appendix C requirement id → level and text. */
  requirements: Map<string, { level: number; description: string; standard: 'asvs' | 'aisvs' | 'aisvs-appendix-c' }>;
  /** Every SbD checklist control id. */
  sbd: Set<string>;
}

let cached: FrameworkIds | undefined;

export function loadFrameworkIds(): FrameworkIds {
  if (cached) return cached;
  const requirements: FrameworkIds['requirements'] = new Map();
  const asvs = readJson<ChapterFramework>(join(FRAMEWORKS_DIR, 'asvs-5.0.0.json'));
  for (const ch of asvs.chapters)
    for (const s of ch.sections)
      for (const r of s.requirements) requirements.set(r.id, { level: r.level, description: r.description, standard: 'asvs' });
  const aisvs = readJson<ChapterFramework>(join(FRAMEWORKS_DIR, 'aisvs-1.0.json'));
  for (const ch of aisvs.chapters)
    for (const s of ch.sections)
      for (const r of s.requirements) requirements.set(r.id, { level: r.level, description: r.description, standard: 'aisvs' });
  const appendix = readJson<AppendixC>(join(FRAMEWORKS_DIR, 'aisvs-1.0-appendix-c.json'));
  for (const f of appendix.families)
    for (const r of f.requirements) requirements.set(r.id, { level: r.level, description: r.description, standard: 'aisvs-appendix-c' });
  const sbd = readJson<SbdChecklist>(join(FRAMEWORKS_DIR, 'sbd-checklist-0.5.0.json'));
  const sbdIds = new Set<string>();
  for (const d of sbd.checklistDomains) for (const c of d.controls) sbdIds.add(c.id);
  cached = { requirements, sbd: sbdIds };
  return cached;
}

/** Requirement ids at level 1 or 2 across all three standards. */
export function levelOneAndTwoIds(): string[] {
  const { requirements } = loadFrameworkIds();
  return [...requirements.entries()].filter(([, v]) => v.level <= 2).map(([id]) => id);
}

export function unknownRequirementIds(ids: string[]): string[] {
  const { requirements } = loadFrameworkIds();
  return ids.filter((id) => !requirements.has(id));
}

export function unknownSbdIds(ids: string[]): string[] {
  const { sbd } = loadFrameworkIds();
  return ids.filter((id) => !sbd.has(id));
}

const ACRONYM_WITHOUT_EXPANSION = /\b(?:XSS|CSRF|SSRF|IDOR|XXE|RCE|JWT|CSP|HSTS|TOTP|OIDC|SAML|PII|PHI|RBAC|CORS)\b/;

/**
 * Plain-language heuristic: sentences must be reasonably short and any hard acronym must be explained
 * on the same text (an expansion in brackets or a "that is" clause). Used as a soft quality gate.
 */
export function plainLanguageProblems(text: string, opts: { checkAcronyms: boolean }): string[] {
  const problems: string[] = [];
  const sentences = text.split(/(?<=[.!?])\s+/).filter(Boolean);
  for (const s of sentences) {
    const words = s.split(/\s+/).length;
    if (words > 45) problems.push(`sentence too long (${words} words): "${s.slice(0, 60)}…"`);
  }
  if (opts.checkAcronyms) {
    const acronym = ACRONYM_WITHOUT_EXPANSION.exec(text);
    if (acronym && !/\(|\bthat is\b|\bmeaning\b|\bi\.e\./.test(text)) {
      problems.push(`acronym ${acronym[0]} used without an explanation`);
    }
  }
  return problems;
}
