/**
 * SecureVibe settings and paths.
 *
 *  - SECUREVIBE_HOME (default <repo>/workspace) holds projects/, settings.json and llm-audit.jsonl.
 *  - SECUREVIBE_PORT (default 4173) is the port the local server listens on (127.0.0.1 only).
 *  - SECUREVIBE_AI=off keeps SecureVibe in preview mode (no AI calls) even when a key is configured.
 *  - settings.json holds the advanced settings the UI can change; "Reset to recommended" restores DEFAULT_SETTINGS.
 *  - The Anthropic key is read from the environment or a .env file next to the repository's package.json; it is never
 *    written anywhere by SecureVibe.
 */
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { writeJsonAtomicSync } from './store/atomic.js';

export const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
export const DEFAULT_PORT = 4173;
export const HOST = '127.0.0.1';

export const SettingsSchema = z.object({
  model: z.string().min(1).default('claude-opus-5'),
  generationEffort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).default('high'),
  reviewEffort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).default('medium'),
  defaultSpendingCapUsd: z.number().min(1).max(500).default(5),
  maxFixRounds: z.number().int().min(0).max(3).default(2),
  storeFullPrompts: z.boolean().default(true),
  /** The "Use AI" switch: when off, SecureVibe runs in preview mode even with a key (no calls, no cost). */
  aiEnabled: z.boolean().default(true),
  /**
   * "Save credits": the cheaper model, the lowest effort and at most one fix round, whatever the advanced settings
   * say. Slower answers are fine; the spending limit still applies on top.
   */
  saveCredits: z.boolean().default(true),
});
export type Settings = z.infer<typeof SettingsSchema>;

/** The model Save credits uses: about 2.5 times cheaper than Opus 5 for the same tokens. */
export const SAVE_CREDITS_MODEL = 'claude-sonnet-5';

/** The AI settings a build actually uses, with Save credits applied. */
export function effectiveAiSettings(settings: Settings): Settings {
  if (!settings.saveCredits) return settings;
  return {
    ...settings,
    model: SAVE_CREDITS_MODEL,
    generationEffort: 'low',
    reviewEffort: 'low',
    maxFixRounds: Math.min(settings.maxFixRounds, 1),
  };
}

export const DEFAULT_SETTINGS: Settings = SettingsSchema.parse({});

export interface Paths {
  repoRoot: string;
  /** SECUREVIBE_HOME: the workspace root. */
  home: string;
  projectsDir: string;
  settingsFile: string;
  auditLogFile: string;
  securityEventsFile: string;
  templateDir: string;
  dataDir: string;
  frameworksDir: string;
  knowledgeDir: string;
  webDist: string;
  selfAssessmentDir: string;
  selfAssessmentProfile: string;
}

export function resolvePaths(env: NodeJS.ProcessEnv = process.env, repoRoot: string = REPO_ROOT): Paths {
  const home = resolve(env['SECUREVIBE_HOME'] && env['SECUREVIBE_HOME'].trim() !== '' ? env['SECUREVIBE_HOME'] : join(repoRoot, 'workspace'));
  return {
    repoRoot,
    home,
    projectsDir: join(home, 'projects'),
    settingsFile: join(home, 'settings.json'),
    auditLogFile: join(home, 'llm-audit.jsonl'),
    securityEventsFile: join(home, 'logs', 'security-events.jsonl'),
    templateDir: join(repoRoot, 'templates', 'secure-web-app'),
    dataDir: join(repoRoot, 'data'),
    frameworksDir: join(repoRoot, 'data', 'frameworks'),
    knowledgeDir: join(repoRoot, 'data', 'knowledge'),
    webDist: join(repoRoot, 'web', 'dist'),
    selfAssessmentDir: join(repoRoot, 'artifacts', 'self-assessment'),
    selfAssessmentProfile: join(repoRoot, 'self-assessment', 'profile.json'),
  };
}

export function portFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env['SECUREVIBE_PORT'];
  if (!raw) return DEFAULT_PORT;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`SECUREVIBE_PORT must be a whole number between 1 and 65535 (got "${raw}").`);
  }
  return n;
}

/** Version from server/package.json (falls back to the repository package.json). */
export function readVersion(repoRoot: string = REPO_ROOT): string {
  for (const file of [join(repoRoot, 'server', 'package.json'), join(repoRoot, 'package.json')]) {
    try {
      const pkg = JSON.parse(readFileSync(file, 'utf8')) as { version?: string };
      if (pkg.version) return pkg.version;
    } catch {
      // try the next file
    }
  }
  return '0.0.0';
}

/**
 * Reads KEY=value lines from <repo>/.env into process.env for keys that are not already set. Only the keys SecureVibe
 * itself understands are imported, so a stray .env cannot change the environment of child processes.
 */
export const DOTENV_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'SECUREVIBE_AI', 'SECUREVIBE_HOME', 'SECUREVIBE_PORT', 'SECUREVIBE_OPEN_BROWSER', 'SECUREVIBE_LOG_LEVEL'] as const;

export function loadDotEnv(repoRoot: string = REPO_ROOT, env: NodeJS.ProcessEnv = process.env): string[] {
  const file = join(repoRoot, '.env');
  if (!existsSync(file)) return [];
  const loaded: string[] = [];
  for (const rawLine of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    // A key pasted on its own line (no "ANTHROPIC_API_KEY=" in front) is an easy mistake; accept it for that key only.
    if (eq < 0 && /^sk-ant-[A-Za-z0-9_-]+$/.test(line)) {
      if (env['ANTHROPIC_API_KEY'] === undefined || env['ANTHROPIC_API_KEY'] === '') {
        env['ANTHROPIC_API_KEY'] = line;
        loaded.push('ANTHROPIC_API_KEY');
      }
      continue;
    }
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!(DOTENV_KEYS as readonly string[]).includes(key)) continue;
    if (value === '') continue; // a blank entry (as in .env.example) means "use the default"
    if (env[key] === undefined || env[key] === '') {
      env[key] = value;
      loaded.push(key);
    }
  }
  return loaded;
}

/** Settings persisted in <home>/settings.json. Unknown or invalid values fall back to the defaults, never crash. */
export class SettingsStore {
  private current: Settings;

  constructor(private readonly file: string) {
    this.current = this.read();
  }

  private read(): Settings {
    if (!existsSync(this.file)) return { ...DEFAULT_SETTINGS };
    try {
      const raw = JSON.parse(readFileSync(this.file, 'utf8')) as unknown;
      const parsed = SettingsSchema.safeParse(raw);
      if (parsed.success) return parsed.data;
    } catch {
      // fall through to the defaults
    }
    return { ...DEFAULT_SETTINGS };
  }

  get(): Settings {
    return { ...this.current };
  }

  update(patch: Partial<Settings>): Settings {
    const next = SettingsSchema.parse({ ...this.current, ...stripUndefined(patch) });
    this.current = next;
    this.persist();
    return this.get();
  }

  reset(): Settings {
    this.current = { ...DEFAULT_SETTINGS };
    this.persist();
    return this.get();
  }

  private persist(): void {
    mkdirSync(resolve(this.file, '..'), { recursive: true });
    writeJsonAtomicSync(this.file, this.current);
  }
}

function stripUndefined<T extends object>(obj: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(obj)) if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  return out;
}

export interface SecureVibeConfig {
  paths: Paths;
  port: number;
  host: string;
  version: string;
  settings: SettingsStore;
  /** Whether to open the browser at startup (SECUREVIBE_OPEN_BROWSER=0 disables it). */
  openBrowser: boolean;
  logLevel: string;
  /** SECUREVIBE_TEST_MODE=1: the ready line and the token are printed as JSON for the self-assessment harness. */
  testMode: boolean;
  /** SECUREVIBE_AI=off: run in preview mode (no AI calls) even when an API key is configured. */
  aiDisabled: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, repoRoot: string = REPO_ROOT): SecureVibeConfig {
  loadDotEnv(repoRoot, env);
  const paths = resolvePaths(env, repoRoot);
  mkdirSync(paths.projectsDir, { recursive: true });
  return {
    paths,
    port: portFromEnv(env),
    host: HOST,
    version: readVersion(repoRoot),
    settings: new SettingsStore(paths.settingsFile),
    openBrowser: env['SECUREVIBE_OPEN_BROWSER'] !== '0',
    logLevel: env['SECUREVIBE_LOG_LEVEL'] ?? 'info',
    testMode: env['SECUREVIBE_TEST_MODE'] === '1',
    aiDisabled: (env['SECUREVIBE_AI'] ?? '').toLowerCase() === 'off',
  };
}
