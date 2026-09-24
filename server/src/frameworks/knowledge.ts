/**
 * Loads data/knowledge/*.json into one validated `Knowledge` object.
 *
 * The three files this module owns (applicability, sbd-rules, patterns) are required and must validate.
 * The others are written by other modules: when a file is missing we log a warning and return an empty
 * structure so the rest of SecureVibe keeps working; when present, it must validate.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { ExampleProjectSchema, type ExampleProject } from '@shared/api.js';
import {
  ApplicabilityConfigSchema,
  PatternCatalogEntrySchema,
  RemediationEntrySchema,
  RequirementPlainSchema,
  SbdRuleSchema,
  type ApplicabilityConfig,
  type PatternCatalogEntry,
  type RemediationEntry,
  type RequirementPlain,
  type SbdRule,
} from '@shared/knowledge.js';
import { KNOWLEDGE_DIR } from './load.js';

/**
 * glossary.json: [{ term, plain }], [{ term, definition }] or { "<term>": "<plain>" } — normalized to entries
 * that always carry `plain` (the writer of the file may call the field `definition`).
 */
export const GlossaryEntrySchema = z.preprocess(
  (raw) => {
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      const entry = raw as Record<string, unknown>;
      if (typeof entry['plain'] !== 'string' && typeof entry['definition'] === 'string') {
        return { ...entry, plain: entry['definition'] };
      }
    }
    return raw;
  },
  z.object({ term: z.string(), plain: z.string(), seeAlso: z.array(z.string()).optional() }).loose(),
);
export type GlossaryEntry = z.infer<typeof GlossaryEntrySchema>;

/** injection-patterns.json: rules used to screen free text before it reaches Claude (§1.11). */
export const InjectionPatternSchema = z
  .object({
    id: z.string(),
    pattern: z.string(),
    flags: z.string().optional(),
    description: z.string().optional(),
    /** Plain-language sentence shown to the user when this rule fires. */
    explanation: z.string().optional(),
  })
  .loose();
export type InjectionPattern = z.infer<typeof InjectionPatternSchema>;
export interface InjectionPatterns {
  /** High-precision rules: block the text and log `ai.input.rejected`. */
  high: InjectionPattern[];
  /** Medium-precision rules: flag (`ai.input.flagged`) and continue. */
  medium: InjectionPattern[];
}

/** wizard-copy.json is free-form UI copy keyed by screen/question; it is passed through as-is. */
export type WizardCopy = Record<string, unknown>;

export interface Knowledge {
  applicability: ApplicabilityConfig;
  sbdRules: SbdRule[];
  patterns: PatternCatalogEntry[];
  /** Keyed by rule id (e.g. "sast.eval-usage"). */
  remediation: Record<string, RemediationEntry>;
  /** Keyed by requirement id (e.g. "V6.2.1"). */
  requirementsPlain: Record<string, RequirementPlain>;
  glossary: GlossaryEntry[];
  wizardCopy: WizardCopy;
  examples: ExampleProject[];
  injectionPatterns: InjectionPatterns;
  /** Files that were absent and replaced by an empty structure. */
  missingFiles: string[];
}

export const KNOWLEDGE_FILES = {
  applicability: 'applicability.json',
  sbdRules: 'sbd-rules.json',
  patterns: 'patterns.json',
  remediation: 'remediation.json',
  requirementsPlain: 'requirements-plain.json',
  glossary: 'glossary.json',
  wizardCopy: 'wizard-copy.json',
  examples: 'examples.json',
  injectionPatterns: 'injection-patterns.json',
} as const;

export interface LoadKnowledgeOptions {
  dir?: string;
  warn?: (message: string) => void;
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, 'utf8')) as unknown;
}

/** Unwraps `{ entries: [...] }`, `{ items: [...] }` and record shapes into an array. */
function toArray(value: unknown, keyName: string): unknown[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    for (const wrapper of ['entries', 'items', 'rules', 'patterns', 'examples', 'terms']) {
      if (Array.isArray(obj[wrapper])) return obj[wrapper] as unknown[];
    }
    return Object.entries(obj).map(([key, entry]) =>
      entry && typeof entry === 'object' && !Array.isArray(entry)
        ? { [keyName]: key, ...(entry as Record<string, unknown>) }
        : { [keyName]: key, plain: entry },
    );
  }
  throw new Error(`expected an array or an object keyed by ${keyName}`);
}

function parseFile<T>(file: string, parse: (raw: unknown) => T): T {
  try {
    return parse(readJson(file));
  } catch (err) {
    const detail = err instanceof z.ZodError ? z.prettifyError(err) : String(err);
    throw new Error(`Knowledge file ${file} is invalid: ${detail}`);
  }
}

function parseInjectionPatterns(raw: unknown): InjectionPatterns {
  // The grouped shape names its lists `high`/`medium` or `highPrecision`/`medium` (CONTRACTS §1.11 wording).
  const grouped = z
    .object({
      high: z.array(InjectionPatternSchema).default([]),
      highPrecision: z.array(InjectionPatternSchema).default([]),
      medium: z.array(InjectionPatternSchema).default([]),
    })
    .loose()
    .safeParse(raw);
  if (grouped.success) {
    const high = [...grouped.data.high, ...grouped.data.highPrecision];
    if (high.length > 0 || grouped.data.medium.length > 0) return { high, medium: grouped.data.medium };
  }
  const flat = z
    .array(InjectionPatternSchema.extend({ precision: z.enum(['high', 'medium']).default('medium') }))
    .parse(toArray(raw, 'id'));
  return {
    high: flat.filter((p) => p.precision === 'high'),
    medium: flat.filter((p) => p.precision === 'medium'),
  };
}

let cache: Knowledge | undefined;

export function loadKnowledge(opts: LoadKnowledgeOptions = {}): Knowledge {
  const dir = opts.dir ?? KNOWLEDGE_DIR;
  if (cache && dir === KNOWLEDGE_DIR) return cache;
  const warn = opts.warn ?? ((message: string) => process.stderr.write(`[knowledge] ${message}\n`));
  const missingFiles: string[] = [];

  const optional = <T>(name: keyof typeof KNOWLEDGE_FILES, empty: T, parse: (raw: unknown) => T): T => {
    const file = join(dir, KNOWLEDGE_FILES[name]);
    if (!existsSync(file)) {
      missingFiles.push(KNOWLEDGE_FILES[name]);
      warn(`${KNOWLEDGE_FILES[name]} is missing; using an empty ${name} until it is written`);
      return empty;
    }
    return parseFile(file, parse);
  };
  const required = <T>(name: keyof typeof KNOWLEDGE_FILES, parse: (raw: unknown) => T): T => {
    const file = join(dir, KNOWLEDGE_FILES[name]);
    if (!existsSync(file)) throw new Error(`Required knowledge file ${file} is missing`);
    return parseFile(file, parse);
  };

  const knowledge: Knowledge = {
    applicability: required('applicability', (raw) => ApplicabilityConfigSchema.parse(raw)),
    sbdRules: required('sbdRules', (raw) => z.array(SbdRuleSchema).parse(toArray(raw, 'id'))),
    patterns: required('patterns', (raw) => z.array(PatternCatalogEntrySchema).parse(toArray(raw, 'id'))),
    remediation: optional('remediation', {}, (raw) =>
      Object.fromEntries(z.array(RemediationEntrySchema).parse(toArray(raw, 'ruleId')).map((e) => [e.ruleId, e])),
    ),
    requirementsPlain: optional('requirementsPlain', {}, (raw) =>
      Object.fromEntries(z.array(RequirementPlainSchema).parse(toArray(raw, 'id')).map((e) => [e.id, e])),
    ),
    glossary: optional('glossary', [], (raw) => z.array(GlossaryEntrySchema).parse(toArray(raw, 'term'))),
    wizardCopy: optional('wizardCopy', {}, (raw) => z.record(z.string(), z.unknown()).parse(raw)),
    examples: optional('examples', [], (raw) => z.array(ExampleProjectSchema).parse(toArray(raw, 'id'))),
    injectionPatterns: optional('injectionPatterns', { high: [], medium: [] }, parseInjectionPatterns),
    missingFiles,
  };
  if (dir === KNOWLEDGE_DIR) cache = knowledge;
  return knowledge;
}

/** Drops the module cache (tests only). */
export function resetKnowledgeCache(): void {
  cache = undefined;
}
