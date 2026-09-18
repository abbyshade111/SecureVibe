/**
 * Typed, cached views over data/frameworks/*.json (ASVS 5.0.0, AISVS 1.0, AISVS Appendix C, SbD 0.5.0).
 *
 * Ids: ASVS "V6.2.1" (chapter V6, section V6.2); AISVS "C2.1.3" (chapter C2, section C2.1);
 * Appendix C "AC.4.1" (family AC.4, which doubles as chapter and section); SbD "AS-01".
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { StandardId } from '@shared/compliance.js';

export const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
export const DATA_DIR = join(REPO_ROOT, 'data');
export const FRAMEWORKS_DIR = join(DATA_DIR, 'frameworks');
export const KNOWLEDGE_DIR = join(DATA_DIR, 'knowledge');

const RequirementJsonSchema = z.object({
  id: z.string(),
  description: z.string(),
  level: z.number().int(),
  cwe: z.array(z.union([z.string(), z.number()])).optional(),
  mappings: z.string().optional(),
});

const AsvsJsonSchema = z.object({
  standard: z.string(),
  version: z.string(),
  source: z.string().optional(),
  license: z.string().optional(),
  chapters: z.array(
    z.object({
      id: z.string(),
      shortName: z.string().optional(),
      name: z.string(),
      sections: z.array(z.object({ id: z.string(), name: z.string(), requirements: z.array(RequirementJsonSchema) })),
    }),
  ),
});

const AisvsJsonSchema = z.object({
  standard: z.string(),
  version: z.string(),
  source: z.string().optional(),
  license: z.string().optional(),
  chapters: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      controlObjective: z.string().optional(),
      sections: z.array(
        z.object({
          id: z.string(),
          name: z.string(),
          description: z.string().optional(),
          requirements: z.array(RequirementJsonSchema),
        }),
      ),
    }),
  ),
});

const AppendixCJsonSchema = z.object({
  standard: z.string(),
  version: z.string(),
  source: z.string().optional(),
  license: z.string().optional(),
  families: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      description: z.string().optional(),
      requirements: z.array(RequirementJsonSchema),
    }),
  ),
});

const SbdJsonSchema = z.object({
  framework: z.string(),
  version: z.string(),
  source: z.string().optional(),
  license: z.string().optional(),
  checklistDomains: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      controls: z.array(
        z.object({
          id: z.string(),
          statement: z.string(),
          critical: z.boolean(),
          severityIfNo: z.enum(['high', 'medium', 'low']),
        }),
      ),
    }),
  ),
  scoring: z.object({
    yes: z.number(),
    'n-a': z.number(),
    no: z.object({ low: z.number(), medium: z.number(), high: z.number() }),
    escalateWhen: z.string(),
    threshold: z.number(),
  }),
  processSteps: z.array(z.string()),
  principles: z.array(z.object({ id: z.string(), name: z.string() })),
  escalationTriggers: z.array(z.object({ id: z.string(), name: z.string() })),
});

export interface RequirementInfo {
  id: string;
  standard: StandardId;
  chapterId: string;
  chapterName: string;
  sectionId: string;
  sectionName: string;
  description: string;
  level: number;
}

export interface SectionInfo {
  id: string;
  name: string;
  requirementIds: string[];
}

export interface ChapterInfo {
  id: string;
  name: string;
  shortName?: string;
  standard: StandardId;
  sections: SectionInfo[];
}

export interface StandardView {
  standard: StandardId;
  name: string;
  version: string;
  source?: string;
  license?: string;
  chapters: ChapterInfo[];
  requirements: RequirementInfo[];
}

export interface SbdControlInfo {
  id: string;
  domain: string; // "A".."E"
  domainName: string;
  statement: string;
  critical: boolean;
  severityIfNo: 'high' | 'medium' | 'low';
}

export interface SbdView {
  framework: string;
  version: string;
  source?: string;
  license?: string;
  domains: { id: string; name: string; controlIds: string[] }[];
  controls: SbdControlInfo[];
  scoring: z.infer<typeof SbdJsonSchema>['scoring'];
  processSteps: string[];
  principles: { id: string; name: string }[];
  escalationTriggers: { id: string; name: string }[];
}

export interface Frameworks {
  asvs: StandardView;
  aisvs: StandardView;
  appendixC: StandardView;
  sbd: SbdView;
  /** Fast lookup for requirement ids of any standard (V6.2.1, C2.1.3, AC.4.1). */
  getRequirement(id: string): RequirementInfo | undefined;
  listRequirements(standard: StandardId): RequirementInfo[];
  chapters(standard: StandardId): ChapterInfo[];
  getSbdControl(id: string): SbdControlInfo | undefined;
  /** True when the id names a known chapter, section or requirement of any standard. */
  hasScope(id: string): boolean;
  /** Requirement ids under a chapter/section/requirement id (empty when unknown). */
  requirementIdsInScope(scope: string): string[];
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, 'utf8')) as unknown;
}

function buildStandard(
  standard: StandardId,
  meta: { standard: string; version: string; source?: string; license?: string },
  chapters: {
    id: string;
    name: string;
    shortName?: string;
    sections: { id: string; name: string; requirements: z.infer<typeof RequirementJsonSchema>[] }[];
  }[],
): StandardView {
  const requirements: RequirementInfo[] = [];
  const chapterInfos: ChapterInfo[] = chapters.map((ch) => ({
    id: ch.id,
    name: ch.name,
    ...(ch.shortName ? { shortName: ch.shortName } : {}),
    standard,
    sections: ch.sections.map((s) => {
      for (const r of s.requirements) {
        requirements.push({
          id: r.id,
          standard,
          chapterId: ch.id,
          chapterName: ch.name,
          sectionId: s.id,
          sectionName: s.name,
          description: r.description,
          level: r.level,
        });
      }
      return { id: s.id, name: s.name, requirementIds: s.requirements.map((r) => r.id) };
    }),
  }));
  return {
    standard,
    name: meta.standard,
    version: meta.version,
    ...(meta.source ? { source: meta.source } : {}),
    ...(meta.license ? { license: meta.license } : {}),
    chapters: chapterInfos,
    requirements,
  };
}

let cache: Frameworks | undefined;

/** Loads and caches the four framework files. Pass a directory only in tests. */
export function loadFrameworks(frameworksDir: string = FRAMEWORKS_DIR): Frameworks {
  if (cache && frameworksDir === FRAMEWORKS_DIR) return cache;

  const asvsJson = AsvsJsonSchema.parse(readJson(join(frameworksDir, 'asvs-5.0.0.json')));
  const aisvsJson = AisvsJsonSchema.parse(readJson(join(frameworksDir, 'aisvs-1.0.json')));
  const appendixJson = AppendixCJsonSchema.parse(readJson(join(frameworksDir, 'aisvs-1.0-appendix-c.json')));
  const sbdJson = SbdJsonSchema.parse(readJson(join(frameworksDir, 'sbd-checklist-0.5.0.json')));

  const asvs = buildStandard('asvs', asvsJson, asvsJson.chapters);
  const aisvs = buildStandard('aisvs', aisvsJson, aisvsJson.chapters);
  // Appendix C has families only: each family is both the chapter and the section.
  const appendixC = buildStandard(
    'aisvs-appendix-c',
    appendixJson,
    appendixJson.families.map((f) => ({
      id: f.id,
      name: f.name,
      sections: [{ id: f.id, name: f.name, requirements: f.requirements }],
    })),
  );

  const controls: SbdControlInfo[] = [];
  const domains = sbdJson.checklistDomains.map((d) => {
    for (const c of d.controls) controls.push({ ...c, domain: d.id, domainName: d.name });
    return { id: d.id, name: d.name, controlIds: d.controls.map((c) => c.id) };
  });
  const sbd: SbdView = {
    framework: sbdJson.framework,
    version: sbdJson.version,
    ...(sbdJson.source ? { source: sbdJson.source } : {}),
    ...(sbdJson.license ? { license: sbdJson.license } : {}),
    domains,
    controls,
    scoring: sbdJson.scoring,
    processSteps: sbdJson.processSteps,
    principles: sbdJson.principles,
    escalationTriggers: sbdJson.escalationTriggers,
  };

  const byStandard: Record<StandardId, StandardView> = { asvs, aisvs, 'aisvs-appendix-c': appendixC };
  const requirementIndex = new Map<string, RequirementInfo>();
  const scopeIndex = new Map<string, string[]>();
  for (const view of Object.values(byStandard)) {
    for (const r of view.requirements) requirementIndex.set(r.id, r);
    for (const ch of view.chapters) {
      scopeIndex.set(
        ch.id,
        ch.sections.flatMap((s) => s.requirementIds),
      );
      for (const s of ch.sections) scopeIndex.set(s.id, [...s.requirementIds]);
    }
  }
  const controlIndex = new Map(controls.map((c) => [c.id, c]));

  const frameworks: Frameworks = {
    asvs,
    aisvs,
    appendixC,
    sbd,
    getRequirement: (id) => requirementIndex.get(id),
    listRequirements: (standard) => byStandard[standard].requirements,
    chapters: (standard) => byStandard[standard].chapters,
    getSbdControl: (id) => controlIndex.get(id),
    hasScope: (id) => requirementIndex.has(id) || scopeIndex.has(id),
    requirementIdsInScope: (scope) => {
      if (requirementIndex.has(scope)) return [scope];
      return scopeIndex.get(scope) ?? [];
    },
  };
  if (frameworksDir === FRAMEWORKS_DIR) cache = frameworks;
  return frameworks;
}

/** Which standard an id belongs to, by its shape (does not check existence). */
export function standardForId(id: string): StandardId | 'sbd' | undefined {
  if (/^AC\.\d+(\.\d+)?$/.test(id)) return 'aisvs-appendix-c';
  if (/^V\d+(\.\d+){0,2}$/.test(id)) return 'asvs';
  if (/^C\d+(\.\d+){0,2}$/.test(id)) return 'aisvs';
  if (/^(AS|DM|RR|AC|MT)-\d\d$/.test(id)) return 'sbd';
  return undefined;
}

/** The section id of a requirement id ("V6.2.1" → "V6.2", "AC.4.1" → "AC.4"). */
export function sectionIdOf(requirementId: string): string {
  return requirementId.slice(0, requirementId.lastIndexOf('.'));
}

/** The chapter id of a requirement or section id ("V6.2.1" → "V6", "AC.4.1" → "AC.4"). */
export function chapterIdOf(id: string): string {
  if (id.startsWith('AC.')) {
    const parts = id.split('.');
    return `${parts[0]}.${parts[1]}`;
  }
  return id.split('.')[0] ?? id;
}
