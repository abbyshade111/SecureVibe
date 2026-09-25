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
import type { LlmPurpose } from './llm/types.js';
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
  /** A desktop notification when a build or check ends (the build runs for minutes, usually unattended). */
  notifyOnFinish: z.boolean().default(true),
  /**
   * Run the virus scanner (ClamAV) over apps SecureVibe built, too. Uploaded apps are always scanned (ADR-011:
   * the clearest untrusted content SecureVibe holds); for an app it wrote itself the scan is off unless asked,
   * because source code is not where virus signatures earn their keep and the scan takes minutes.
   */
  scanBuiltAppsForMalware: z.boolean().default(false),
  /** The AI service everything uses unless a step below says otherwise; it needs a key for that service. */
  aiService: z.enum(['anthropic', 'openai', 'google']).default('anthropic'),
  /**
   * Which service does which step ('default' = the one above). Three groups, because those are the choices that
   * make a difference to the owner: what writes the app, what reviews it, and the small questions in between.
   * A review by a service that did not write the code is an independent check, and the reports say who did what.
   * The web app always sends all three values together.
   */
  /**
   * nano-analyzer: an experimental AI scanner (https://github.com/weareaisle/nano-analyzer) that reads the app's
   * code and suggests what to look at. Off, because switching it on sends your code to OpenAI (or OpenRouter) and
   * spends money on your own key there. Its suggestions are never evidence; see scanners/external/nano-analyzer.ts.
   */
  nanoAnalyzer: z
    .object({
      enabled: z.boolean().default(false),
      /** The full path of the nano-analyzer folder you downloaded, or of its scan.py. */
      scriptPath: z.string().default(''),
      model: z.string().min(1).default('gpt-5.4-nano'),
      /** Only suggestions this share of the tool's own triage rounds agreed on are shown (0.7 = 70%). */
      minConfidence: z.number().min(0).max(1).default(0.7),
    })
    .default({ enabled: false, scriptPath: '', model: 'gpt-5.4-nano', minConfidence: 0.7 }),
  aiServiceFor: z
    .object({
      write: z.enum(['default', 'anthropic', 'openai', 'google']).default('default'),
      review: z.enum(['default', 'anthropic', 'openai', 'google']).default('default'),
      questions: z.enum(['default', 'anthropic', 'openai', 'google']).default('default'),
    })
    .default({ write: 'default', review: 'default', questions: 'default' }),
});
export type Settings = z.infer<typeof SettingsSchema>;
export type AiServiceId = Settings['aiService'];
export type AiStepGroup = keyof Settings['aiServiceFor'];

/** Which group each AI step belongs to. */
const STEP_GROUP: Record<LlmPurpose, AiStepGroup> = {
  generate: 'write',
  fix: 'write',
  'ai-review': 'review',
  'quick-infer': 'questions',
  'peer-review': 'questions',
  refine: 'questions',
  plan: 'questions',
  'threat-model': 'questions',
  classify: 'questions',
  summarize: 'questions',
};

export const STEP_GROUP_LABEL: Record<AiStepGroup, string> = {
  write: 'Writing your app',
  review: 'Reviewing the code',
  questions: 'Questions, plans and second opinions',
};

export function stepGroupFor(purpose: LlmPurpose): AiStepGroup {
  return STEP_GROUP[purpose];
}

/** The service a step uses: its own choice, or the default when it says 'default'. */
export function serviceForPurpose(settings: Settings, purpose?: LlmPurpose): AiServiceId {
  if (!purpose) return settings.aiService;
  const chosen = settings.aiServiceFor[stepGroupFor(purpose)];
  return chosen === 'default' ? settings.aiService : chosen;
}

/** The model Save credits uses: about 2.5 times cheaper than Opus 5 for the same tokens. */
export const SAVE_CREDITS_MODEL = 'claude-sonnet-5';
/** The cheaper model of each service for Save credits, and each service's default model. */
export const SAVE_CREDITS_MODELS: Record<AiServiceId, string> = { anthropic: SAVE_CREDITS_MODEL, openai: 'gpt-5-mini', google: 'gemini-2.5-flash' };
export const DEFAULT_MODELS: Record<AiServiceId, string> = { anthropic: 'claude-opus-5', openai: 'gpt-5', google: 'gemini-2.5-pro' };
const MODEL_PREFIX: Record<AiServiceId, RegExp> = { anthropic: /^claude-/, openai: /^(gpt-|o\d)/, google: /^gemini-/ };

/**
 * The small steps, and the cheap model each service runs them on.
 *
 * Two of the AI steps are not judgment about your app: `classify` scores a piece of text for the moderation
 * setting, and `summarize` rewrites technical wording in plain language. Both are short, both are checked by the
 * code around them, and neither decides anything about security, so paying the top rate for them is waste. They run
 * on the cheapest model of whichever service the step belongs to, whatever model is chosen for the rest.
 *
 * Writing your app, reviewing it, planning and second opinions are not in this list: those are judgment, and they
 * use the model you chose. Every call's model and cost is recorded in the audit file either way.
 */
export const SMALL_STEPS: ReadonlySet<LlmPurpose> = new Set<LlmPurpose>(['classify', 'summarize']);
export const SMALL_STEP_MODELS: Record<AiServiceId, string> = { anthropic: 'claude-haiku-4-5', openai: 'gpt-5-mini', google: 'gemini-2.5-flash' };

/** A model name belongs to one service; a name from another service falls back to the chosen service's default. */
export function modelForService(service: AiServiceId, model: string): string {
  return MODEL_PREFIX[service].test(model) ? model : DEFAULT_MODELS[service];
}

/**
 * The AI settings one step actually uses: its service, a model that belongs to that service, and Save credits
 * applied. Without a purpose this is the default service, which is what the estimate and the status page show.
 */
export function effectiveAiSettings(settings: Settings, purpose?: LlmPurpose): Settings {
  const service = serviceForPurpose(settings, purpose);
  // A small step runs on the cheap model of its service, whether or not Save credits is on (see SMALL_STEPS).
  if (purpose && SMALL_STEPS.has(purpose)) {
    return { ...settings, aiService: service, model: SMALL_STEP_MODELS[service] };
  }
  if (!settings.saveCredits) {
    const model = modelForService(service, settings.model);
    return model === settings.model && service === settings.aiService ? settings : { ...settings, aiService: service, model };
  }
  return {
    ...settings,
    aiService: service,
    model: SAVE_CREDITS_MODELS[service],
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
export const DOTENV_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'OPENROUTER_API_KEY', 'SECUREVIBE_AI', 'SECUREVIBE_HOME', 'SECUREVIBE_PORT', 'SECUREVIBE_OPEN_BROWSER', 'SECUREVIBE_LOG_LEVEL'] as const;

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
