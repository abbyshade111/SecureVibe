/**
 * Prompt-injection screening. The ruleset is a data file (data/injection-patterns.json), not code, so it can be
 * updated without touching the app: SecureVibe replaces it with its full knowledge-base list when it scaffolds
 * an app. Two lists:
 *   - highPrecision: phrasings that only appear in manipulation attempts. A match blocks the request.
 *   - medium: phrasings that are often innocent. A match is recorded and the request continues.
 * The same screening runs over application data before it is put in front of the model, because a record can
 * carry an instruction just as easily as a question can.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { APP_ROOT } from '../../config.ts';
import { logger } from '../../lib/logger.ts';

export const INJECTION_PATTERNS_FILE = resolve(APP_ROOT, 'data', 'injection-patterns.json');

export interface InjectionRule {
  id: string;
  regex: RegExp;
  description: string;
  severity: 'high' | 'medium';
}

export type ScreeningResult =
  | { decision: 'clean' }
  | { decision: 'flag'; rule: string; description: string }
  | { decision: 'block'; rule: string; description: string };

interface RawRule {
  id?: unknown;
  pattern?: unknown;
  flags?: unknown;
  description?: unknown;
}

let cache: InjectionRule[] | undefined;

function compile(list: unknown, severity: 'high' | 'medium'): InjectionRule[] {
  if (!Array.isArray(list)) return [];
  const rules: InjectionRule[] = [];
  for (const entry of list as RawRule[]) {
    const id = typeof entry?.id === 'string' ? entry.id : '';
    const pattern = typeof entry?.pattern === 'string' ? entry.pattern : '';
    if (!id || !pattern) continue;
    const flags = typeof entry.flags === 'string' ? entry.flags : '';
    try {
      rules.push({
        id,
        regex: new RegExp(pattern, flags.includes('g') ? flags.replace(/g/g, '') : flags),
        description: typeof entry.description === 'string' ? entry.description : '',
        severity,
      });
    } catch (err) {
      logger.warn({ rule: id, detail: (err as Error).message }, 'injection rule skipped: the pattern is not a valid expression');
    }
  }
  return rules;
}

/** Reads and compiles the ruleset once. A missing or broken file is a warning, never a crash. */
export function injectionRules(): InjectionRule[] {
  if (cache) return cache;
  try {
    const parsed = JSON.parse(readFileSync(INJECTION_PATTERNS_FILE, 'utf8')) as Record<string, unknown>;
    const high = compile(parsed.highPrecision ?? parsed.high, 'high');
    const medium = compile(parsed.medium, 'medium');
    cache = [...high, ...medium];
    logger.info({ high: high.length, medium: medium.length }, 'injection screening ruleset loaded');
  } catch (err) {
    cache = [];
    logger.warn(
      { file: INJECTION_PATTERNS_FILE, detail: (err as Error).message },
      'the prompt-injection ruleset could not be read; the assistant continues with the other checks only',
    );
  }
  return cache;
}

/** High-precision matches block, medium matches are reported and allowed. The first match wins. */
export function screenForInjection(text: string): ScreeningResult {
  for (const rule of injectionRules()) {
    rule.regex.lastIndex = 0;
    if (!rule.regex.test(text)) continue;
    return { decision: rule.severity === 'high' ? 'block' : 'flag', rule: rule.id, description: rule.description };
  }
  return { decision: 'clean' };
}

/** Test and tooling hook: forget the cached ruleset so the file is read again. */
export function resetInjectionRules(): void {
  cache = undefined;
}
