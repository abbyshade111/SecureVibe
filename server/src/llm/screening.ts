/**
 * Prompt-injection screening for untrusted text (user free text, file contents, tool results) — AISVS C2.1.3,
 * Appendix C AC.3.3. Uses the ruleset in data/knowledge/injection-patterns.json: high-precision rules block,
 * medium rules flag. The note is written for the person using SecureVibe.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface InjectionPattern {
  id: string;
  pattern: string;
  flags?: string;
  description?: string;
}

/** Same shape as `Knowledge.injectionPatterns` from server/src/frameworks (structural, no import needed). */
export interface InjectionPatterns {
  high: InjectionPattern[];
  medium: InjectionPattern[];
}

export interface ScreeningRuleHit {
  id: string;
  level: 'high' | 'medium';
  description: string;
}

export interface ScreeningResult {
  /** Any rule matched (high or medium). */
  flagged: boolean;
  /** A high-precision rule matched: the text must not be sent as instructions. */
  blocked: boolean;
  rules: ScreeningRuleHit[];
  /** Plain-language explanation shown to the user (empty when nothing matched). */
  note: string;
}

const compiled = new WeakMap<InjectionPatterns, { high: CompiledRule[]; medium: CompiledRule[] }>();

interface CompiledRule {
  id: string;
  re: RegExp;
  description: string;
}

function compile(list: InjectionPattern[]): CompiledRule[] {
  const out: CompiledRule[] = [];
  for (const p of list) {
    try {
      const flags = (p.flags ?? 'i').replace(/g/g, '');
      out.push({ id: p.id, re: new RegExp(p.pattern, flags), description: p.description ?? p.id });
    } catch {
      // An invalid pattern in the knowledge file must not disable screening; it is simply skipped.
    }
  }
  return out;
}

function rulesFor(patterns: InjectionPatterns): { high: CompiledRule[]; medium: CompiledRule[] } {
  let c = compiled.get(patterns);
  if (!c) {
    c = { high: compile(patterns.high ?? []), medium: compile(patterns.medium ?? []) };
    compiled.set(patterns, c);
  }
  return c;
}

/** NFKC-normalise and drop zero-width / bidi control characters that are used to hide instructions. */
export function normalizeForScreening(text: string): string {
  return text.normalize('NFKC').replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, '');
}

export function screenText(text: string, patterns: InjectionPatterns): ScreeningResult {
  const normalized = normalizeForScreening(text);
  const rules = rulesFor(patterns);
  const hits: ScreeningRuleHit[] = [];
  for (const r of rules.high) if (r.re.test(normalized)) hits.push({ id: r.id, level: 'high', description: r.description });
  for (const r of rules.medium) if (r.re.test(normalized)) hits.push({ id: r.id, level: 'medium', description: r.description });
  const blocked = hits.some((h) => h.level === 'high');
  const flagged = hits.length > 0;
  return { flagged, blocked, rules: hits, note: screeningNote(hits, blocked) };
}

function screeningNote(hits: ScreeningRuleHit[], blocked: boolean): string {
  if (hits.length === 0) return '';
  const first = hits.find((h) => h.level === 'high') ?? hits[0]!;
  const what = first.description.replace(/\.$/, '').toLowerCase();
  if (blocked) {
    return (
      `Part of this text looks like an instruction aimed at the AI (${what}). ` +
      'To keep your app safe we did not send it to the AI. Please describe your app in your own words and try again.'
    );
  }
  return (
    `Part of this text looks like it could be an instruction aimed at the AI (${what}). ` +
    'We passed it on as plain information only; it cannot change how the AI works or the security rules.'
  );
}

let defaultPatterns: InjectionPatterns | undefined;

/** Loads data/knowledge/injection-patterns.json (cached). Missing file → empty ruleset (screening never throws). */
export function loadDefaultInjectionPatterns(): InjectionPatterns {
  if (defaultPatterns) return defaultPatterns;
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(here, '../../../data/knowledge/injection-patterns.json'),
    resolve(process.cwd(), 'data/knowledge/injection-patterns.json'),
    resolve(process.cwd(), '../data/knowledge/injection-patterns.json'),
  ];
  for (const file of candidates) {
    if (!existsSync(file)) continue;
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      const high = (raw.high ?? raw.highPrecision ?? []) as InjectionPattern[];
      const medium = (raw.medium ?? []) as InjectionPattern[];
      defaultPatterns = { high: Array.isArray(high) ? high : [], medium: Array.isArray(medium) ? medium : [] };
      return defaultPatterns;
    } catch {
      break;
    }
  }
  defaultPatterns = { high: [], medium: [] };
  return defaultPatterns;
}
