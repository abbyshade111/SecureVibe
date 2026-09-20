/**
 * Environment configuration. Every setting the app needs comes from the environment (or the local `.env`
 * file written by `npm run setup`). Nothing secret lives in code. Validation fails fast with a plain message
 * that names the variable, so a misconfigured app never starts half-secured.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { loadSecrets } from './lib/secrets.ts';
import { THEMES, DEFAULT_THEME, type Theme } from './lib/themes.ts';

export const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Values that `.env.example` ships with. The app refuses to start while any of them is still in use. */
export const PLACEHOLDER_SECRETS = [
  '__generate_with_npm_run_setup__',
  'changeme',
  'change-me',
  'replace-me',
  'secret',
  'password',
] as const;

/** The looks a person can choose (see lib/themes.ts); re-exported so callers keep one import. */
export { THEMES, DEFAULT_THEME, type Theme } from './lib/themes.ts';

const bool = z
  .enum(['0', '1', 'true', 'false'])
  .transform((v) => v === '1' || v === 'true');

const positiveInt = (name: string, fallback: number) =>
  z
    .string()
    .optional()
    .transform((v, ctx) => {
      if (v === undefined || v === '') return fallback;
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0) {
        ctx.addIssue({ code: 'custom', message: `${name} must be a whole number (got "${v}").` });
        return z.NEVER;
      }
      return n;
    });

function decodedLength(value: string): number {
  // Accept base64, base64url or hex. Anything else counts as raw text bytes.
  const trimmed = value.trim();
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) return trimmed.length / 2;
  if (/^[A-Za-z0-9+/=_-]+$/.test(trimmed)) return Buffer.from(trimmed, 'base64').length;
  return Buffer.byteLength(trimmed, 'utf8');
}

function isPlaceholder(value: string): boolean {
  const v = value.trim().toLowerCase();
  return PLACEHOLDER_SECRETS.some((p) => v === p || v.includes('generate_with_npm_run_setup'));
}

const strongSecret = (name: string) =>
  z
    .string({ message: `${name} is missing. Run "npm run setup" to generate it.` })
    .refine((v) => !isPlaceholder(v), {
      message: `${name} still has the example placeholder value. Run "npm run setup" to generate a real secret.`,
    })
    .refine((v) => decodedLength(v) >= 32, {
      message: `${name} is too short. It must decode to at least 32 bytes. Run "npm run setup" to generate it.`,
    });

/** `FIELD_KEYS` looks like `1:<base64 32 bytes>,2:<base64 32 bytes>`. */
export function parseFieldKeys(raw: string): Map<number, Buffer> {
  const keys = new Map<number, Buffer>();
  for (const part of raw.split(',')) {
    const entry = part.trim();
    if (!entry) continue;
    const idx = entry.indexOf(':');
    if (idx <= 0) throw new Error(`FIELD_KEYS entry "${entry.slice(0, 8)}…" must look like "<id>:<base64 key>".`);
    const id = Number(entry.slice(0, idx));
    const key = Buffer.from(entry.slice(idx + 1).trim(), 'base64');
    if (!Number.isInteger(id) || id < 1) throw new Error('FIELD_KEYS ids must be whole numbers starting at 1.');
    if (key.length !== 32) throw new Error(`FIELD_KEYS key ${id} must decode to exactly 32 bytes.`);
    if (isPlaceholder(entry.slice(idx + 1))) throw new Error('FIELD_KEYS still has the example placeholder value.');
    keys.set(id, key);
  }
  if (keys.size === 0) throw new Error('FIELD_KEYS is empty. Run "npm run setup" to generate it.');
  return keys;
}

const EnvSchema = z.object({
  NODE_ENV: z.enum(['production', 'development', 'test']).default('production'),
  PORT: positiveInt('PORT', 3000),
  BIND_LAN: bool.default(false),
  TLS_MODE: z.enum(['off', 'selfsigned', 'proxy']).default('off'),
  TRUST_PROXY_HOPS: positiveInt('TRUST_PROXY_HOPS', 0),
  DATA_DIR: z.string().default('./data'),
  SESSION_SECRET: strongSecret('SESSION_SECRET'),
  FIELD_KEYS: z.string({ message: 'FIELD_KEYS is missing. Run "npm run setup" to generate it.' }),
  ACTIVE_FIELD_KEY: positiveInt('ACTIVE_FIELD_KEY', 1),
  TOKEN_HMAC_KEY: strongSecret('TOKEN_HMAC_KEY'),
  SESSION_IDLE_MINUTES: z.string().optional(),
  SESSION_ABSOLUTE_HOURS: z.string().optional(),
  SESSION_MAX_CONCURRENT: z.string().optional(),
  ADMIN_MFA_REQUIRED: bool.default(true),
  USER_MFA_AVAILABLE: bool.default(true),
  RATE_LIMIT_GENERAL_PER_MIN: z.string().optional(),
  RATE_LIMIT_LOGIN_PER_ACCOUNT: z.string().optional(),
  RATE_LIMIT_LOGIN_PER_IP: z.string().optional(),
  RATE_LIMIT_MFA_PER_ACCOUNT: z.string().optional(),
  RATE_LIMIT_REGISTRATION_PER_HOUR: z.string().optional(),
  RATE_LIMIT_RESET_PER_ACCOUNT: z.string().optional(),
  RATE_LIMIT_RESET_PER_IP: z.string().optional(),
  RATE_LIMIT_AI_PER_HOUR: z.string().optional(),
  RATE_LIMIT_UPLOADS_PER_HOUR: z.string().optional(),
  RATE_LIMIT_API_KEY_PER_MIN: z.string().optional(),
  OUTBOUND_ALLOWED_HOSTS: z.string().default(''),
  UPLOAD_MAX_BYTES: positiveInt('UPLOAD_MAX_BYTES', 10485760),
  UPLOAD_ALLOWED_TYPES: z.string().default('image/png,image/jpeg,image/gif,image/webp,application/pdf'),
  UPLOAD_USER_QUOTA_BYTES: positiveInt('UPLOAD_USER_QUOTA_BYTES', 209715200),
  AI_ENABLED: bool.default(true),
  AI_MODEL: z.string().default('claude-opus-5'),
  AI_MAX_INPUT_CHARS: positiveInt('AI_MAX_INPUT_CHARS', 8000),
  /**
   * SecureVibe's app preview: a one-time value that turns GET /preview-signin?t=... into a sign-in as the first
   * administrator, so somebody trying the app out is not asked for a password. Only honoured on a loopback-only,
   * plain-http app (that is what a preview is); never set it in a real deployment.
   */
  PREVIEW_SIGNIN_TOKEN: z.string().default(''),
  /** Lets the assistant search the web through the model provider's own search tool (the app itself never crawls). */
  AI_WEB_SEARCH: bool.default(false),
  AI_WEB_SEARCH_MAX_USES: positiveInt('AI_WEB_SEARCH_MAX_USES', 5),
  /** Comma-separated host list the search may return results from; empty means no restriction. */
  AI_WEB_SEARCH_DOMAINS: z.string().default(''),
  AI_MAX_OUTPUT_TOKENS: positiveInt('AI_MAX_OUTPUT_TOKENS', 1024),
  AI_USER_DAILY_TOKENS: positiveInt('AI_USER_DAILY_TOKENS', 200000),
  AI_MODERATION: bool.default(false),
  EXAMPLE_FEATURE: bool.default(false),
  /**
   * `silent` turns logging off entirely, which pino supports and a test run asks for. It was missing here, so an app
   * given LOG_LEVEL=silent refused to start with a message listing every level except the one that was asked for.
   */
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']).default('info'),
  LOG_FILE: z.string().optional(),
  AUDIT_RETENTION_DAYS: positiveInt('AUDIT_RETENTION_DAYS', 400),
  RETENTION_MONTHS: z.string().optional(),
  /**
   * Whether uploaded files are checked for known-bad content, and where the scanner is (ADR-011). The default
   * is the ClamAV daemon on this machine, so an app is safe without being configured. "off" does not mean
   * "accept anything": it means uploads are refused, because a file that was not checked does not get in.
   */
  MALWARE_SCANNER: z.enum(['clamd', 'off']).optional(),
  CLAMD_SOCKET: z.string().optional(),
  CLAMD_HOST: z.string().optional(),
  CLAMD_PORT: z.string().optional(),
  CLAMD_TIMEOUT_MS: z.string().optional(),
  SECUREVIBE_TEST_MODE: bool.optional(),
  SECUREVIBE_TEST_PASSWORD: z.string().optional(),
  SECUREVIBE_TEST_TOTP_SEED: z.string().optional(),
  APP_NAME: z.string().max(80).optional(),
  /** The chosen look. Omitted means the one in securevibe.design.json, and failing that the default. */
  APP_THEME: z.enum(THEMES).optional(),
  REGISTRATION_MODE: z.enum(['open', 'invite-only', 'admin-created']).optional(),
  ADMIN_EMAIL: z.string().optional(),
  SMTP_URL: z.string().optional(),
  MAIL_FROM: z.string().optional(),
});

/** SecureVibe writes the file with the manifest's feature ids; the app's flags are camelCase. Both spellings are kept. */
const FEATURE_KEY_ALIASES: Record<string, string> = {
  'admin-mfa': 'adminMfa',
  'user-mfa': 'userMfa',
  'ai-actions': 'aiActions',
  'ai-moderation': 'aiModeration',
  'ai-history': 'aiHistory',
  'public-api': 'publicApi',
  'field-encryption': 'fieldEncryption',
  retention: 'retentionJobs',
  'retention-jobs': 'retentionJobs',
  'lan-binding': 'lanBinding',
  'tls-mode': 'tlsMode',
};

export function withCamelCaseFeatureKeys(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, unknown> = { ...(raw as Record<string, unknown>) };
  for (const [kebab, camel] of Object.entries(FEATURE_KEY_ALIASES)) {
    if (kebab in out && !(camel in out)) out[camel] = out[kebab];
  }
  return out;
}

/** Feature toggles written by SecureVibe at scaffold time (`securevibe.features.json`). Core features default on. */
export const FeaturesFileSchema = z.looseObject({
  auth: z.boolean().default(true),
  adminMfa: z.boolean().default(true),
  userMfa: z.boolean().default(true),
  uploads: z.boolean().default(false),
  ai: z.boolean().default(false),
  aiActions: z.boolean().default(false),
  aiModeration: z.boolean().default(false),
  aiHistory: z.boolean().default(false),
  email: z.boolean().default(false),
  scheduler: z.boolean().default(false),
  publicApi: z.boolean().default(false),
  payments: z.boolean().default(false),
  fieldEncryption: z.boolean().default(true),
  retentionJobs: z.boolean().default(false),
  lanBinding: z.boolean().default(false),
  tlsMode: z.enum(['off', 'selfsigned', 'proxy']).default('off'),
  example: z.boolean().default(false),
});
export type Features = z.infer<typeof FeaturesFileSchema>;

/**
 * Design inputs written by SecureVibe at scaffold time (`securevibe.design.json`). Every field is optional so the
 * template also runs stand-alone with sensible defaults. The shape mirrors the SecureVibe design profile.
 */
const RoleSchema = z.looseObject({
  name: z.string().min(1).max(40),
  label: z.string().max(60).optional(),
  description: z.string().max(200).optional(),
  isAdmin: z.boolean().default(false),
});
const EntityFieldDesignSchema = z.looseObject({
  name: z.string(),
  label: z.string().optional(),
  type: z.string().optional(),
  required: z.boolean().optional(),
  sensitive: z.boolean().default(false),
  description: z.string().optional(),
});
const EntityDesignSchema = z.looseObject({
  name: z.string(),
  label: z.string().optional(),
  pluralLabel: z.string().optional(),
  description: z.string().optional(),
  fields: z.array(EntityFieldDesignSchema).default([]),
  access: z.string().optional(),
});
const AdrDesignSchema = z.looseObject({
  id: z.string(),
  title: z.string(),
  status: z.string().default('accepted'),
  date: z.string().optional(),
  context: z.string().default(''),
  decision: z.string().default(''),
  alternatives: z.array(z.string()).default([]),
  consequences: z.string().default(''),
  relatedControls: z.array(z.string()).default([]),
  relatedRequirements: z.array(z.string()).default([]),
});
export const DesignFileSchema = z.looseObject({
  profile: z
    .looseObject({
      app: z
        .looseObject({
          name: z.string().optional(),
          tagline: z.string().optional(),
          description: z.string().optional(),
          category: z.string().optional(),
          theme: z.enum(THEMES).optional(),
          entities: z.array(EntityDesignSchema).default([]),
        })
        .optional(),
      users: z
        .looseObject({
          audience: z.string().optional(),
          requiresSignIn: z.boolean().optional(),
          roles: z.array(RoleSchema).default([]),
          registration: z.enum(['invite-only', 'admin-created', 'open']).optional(),
          adminMfa: z.boolean().optional(),
        })
        .optional(),
      data: z
        .looseObject({
          categories: z.array(z.string()).default([]),
          aboutOtherPeople: z.boolean().optional(),
          retention: z.enum(['keep-until-deleted', 'auto-delete-after-period']).optional(),
          retentionMonths: z.number().optional(),
          region: z.string().optional(),
        })
        .optional(),
      capabilities: z.looseObject({}).optional(),
      deployment: z
        .looseObject({
          target: z.string().optional(),
          owner: z.looseObject({ name: z.string().optional(), contactEmail: z.string().optional() }).optional(),
          businessImpact: z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  targetLevel: z.number().int().optional(),
  adrs: z.array(AdrDesignSchema).default([]),
  securityRequirements: z.array(z.looseObject({ id: z.string(), statement: z.string() })).default([]),
  threatSummary: z.string().optional(),
});
export type DesignFile = z.infer<typeof DesignFileSchema>;

export interface RoleDefinition {
  name: string;
  label: string;
  isAdmin: boolean;
}

/** Reads KEY=value lines from a .env file. Values already present in the environment win. */
export function loadDotEnv(file: string, target: NodeJS.ProcessEnv = process.env): void {
  if (!existsSync(file)) return;
  const text = readFileSync(file, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!/^[A-Z][A-Z0-9_]*$/.test(key)) continue;
    if (target[key] === undefined) target[key] = value;
  }
}

function readJsonIfPresent(file: string): unknown {
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`${file} is not valid JSON: ${(err as Error).message}`);
  }
}

function formatIssues(err: z.ZodError): string {
  return err.issues
    .map((i) => {
      const name = i.path.join('.');
      if (i.message.includes(name) || !name) return `- ${i.message}`;
      return `- ${name}: ${i.message}`;
    })
    .join('\n');
}

export interface AppConfig extends Omit<z.infer<typeof EnvSchema>, 'SESSION_IDLE_MINUTES' | 'SESSION_ABSOLUTE_HOURS' | 'SESSION_MAX_CONCURRENT'> {
  /** Absolute data directory (database, uploads, logs). */
  dataDir: string;
  logFile: string;
  appName: string;
  /** The look the pages are rendered with; always one of THEMES. */
  theme: Theme;
  registrationMode: 'open' | 'invite-only' | 'admin-created';
  targetLevel: 1 | 2;
  sessionIdleMinutes: number;
  sessionAbsoluteHours: number;
  sessionMaxConcurrent: number;
  fieldKeys: Map<number, Buffer>;
  testMode: boolean;
  /** Where uploaded files get checked for known-bad content. Never absent: "none" refuses uploads. */
  malwareScanner: MalwareScanner;
  tlsEnabled: boolean;
  roles: RoleDefinition[];
  adminRole: string;
  features: Features;
  design: DesignFile;
  outboundAllowedHosts: string[];
  /** True when this process is a SecureVibe app preview with one-click sign-in (see PREVIEW_SIGNIN_TOKEN). */
  previewMode: boolean;
  /** True when the assistant may search the web through the model provider (AI_WEB_SEARCH, needs AI_ENABLED). */
  aiWebSearch: boolean;
  /** Hosts the web search may return results from; empty means no restriction. */
  aiWebSearchDomains: string[];
  retentionMonths: number | undefined;
  rateLimits: {
    generalPerMin: number;
    loginPerAccount: number;
    loginPerIp: number;
    mfaPerAccount: number;
    registrationPerHour: number;
    resetPerAccount: number;
    resetPerIp: number;
    aiPerHour: number;
    uploadsPerHour: number;
    apiKeyPerMin: number;
  };
}

/**
 * `clamd` is a real scanner. `test` is the app's own suite standing in for one and checks nothing real. `none`
 * means uploads are refused outright. There is deliberately no option that accepts a file without checking it.
 */
export type MalwareScanner =
  | { kind: 'clamd'; socketPath: string; timeoutMs: number }
  | { kind: 'clamd'; host: string; port: number; timeoutMs: number }
  | { kind: 'test' }
  | { kind: 'none' };

function optionalNumber(raw: string | undefined, name: string): number | undefined {
  if (raw === undefined || raw === '') return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${name} must be a positive number (got "${raw}").`);
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  // A host's own secret store first, when one is configured; then the .env file beside the app, which is the
  // default and what SecureVibe sets up. Values already in the environment always win, so a host that injects
  // real environment variables needs neither. See src/lib/secrets.ts and docs/adr/0002-secrets.md.
  loadSecrets({ target: env });
  loadDotEnv(resolve(APP_ROOT, '.env'), env);

  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`The app cannot start because its configuration is incomplete or unsafe:\n${formatIssues(parsed.error)}`);
  }
  const e = parsed.data;

  if (e.SECUREVIBE_TEST_MODE && e.NODE_ENV !== 'test') {
    throw new Error(
      'SECUREVIBE_TEST_MODE=1 is only allowed together with NODE_ENV=test. Remove it from .env before running the app for real.',
    );
  }
  const testMode = e.NODE_ENV === 'test' && e.SECUREVIBE_TEST_MODE === true;
  if (testMode && (!e.SECUREVIBE_TEST_PASSWORD || e.SECUREVIBE_TEST_PASSWORD.length < 16)) {
    throw new Error('Test mode needs SECUREVIBE_TEST_PASSWORD with at least 16 characters.');
  }

  const fieldKeys = parseFieldKeys(e.FIELD_KEYS);
  if (!fieldKeys.has(e.ACTIVE_FIELD_KEY)) {
    throw new Error(`ACTIVE_FIELD_KEY=${e.ACTIVE_FIELD_KEY} does not match any id in FIELD_KEYS.`);
  }

  const rawFeatures = readJsonIfPresent(resolve(APP_ROOT, 'securevibe.features.json'));
  const features = FeaturesFileSchema.parse(withCamelCaseFeatureKeys(rawFeatures ?? {}));
  const rawDesign = readJsonIfPresent(resolve(APP_ROOT, 'securevibe.design.json'));
  const design = DesignFileSchema.parse(rawDesign ?? {});

  const designRoles: RoleDefinition[] = (design.profile?.users?.roles ?? []).map((r) => ({
    name: r.name,
    label: r.label ?? r.name,
    isAdmin: r.isAdmin,
  }));
  const roles: RoleDefinition[] =
    designRoles.length > 0
      ? designRoles
      : [
          { name: 'admin', label: 'Administrator', isAdmin: true },
          { name: 'staff', label: 'Staff', isAdmin: false },
          { name: 'member', label: 'Member', isAdmin: false },
        ];
  if (!roles.some((r) => r.isAdmin)) roles.unshift({ name: 'admin', label: 'Administrator', isAdmin: true });
  const adminRole = roles.find((r) => r.isAdmin)?.name ?? 'admin';

  const targetLevel: 1 | 2 = design.targetLevel === 1 ? 1 : 2;
  const sessionDefaults = targetLevel === 2 ? { idle: 15, absolute: 8, max: 5 } : { idle: 30, absolute: 12, max: 5 };

  const tlsMode = e.TLS_MODE;
  if (tlsMode === 'proxy' && e.TRUST_PROXY_HOPS < 1) {
    throw new Error('TLS_MODE=proxy means the app sits behind a reverse proxy, so TRUST_PROXY_HOPS must be at least 1.');
  }

  const dataDir = isAbsolute(e.DATA_DIR) ? e.DATA_DIR : resolve(APP_ROOT, e.DATA_DIR);
  const logFile = e.LOG_FILE ? (isAbsolute(e.LOG_FILE) ? e.LOG_FILE : resolve(APP_ROOT, e.LOG_FILE)) : resolve(dataDir, 'app.log');

  const generalDefault = testMode ? 100000 : 300;

  const cfg: AppConfig = {
    ...e,
    dataDir,
    logFile,
    appName: e.APP_NAME ?? design.profile?.app?.name ?? 'My App',
    // APP_THEME or the default, and nothing in between: the design snapshot used to offer a third opinion and
    // was the stale one, so an app with no APP_THEME rendered a colour its owner had stopped using.
    theme: e.APP_THEME ?? DEFAULT_THEME,
    registrationMode: e.REGISTRATION_MODE ?? design.profile?.users?.registration ?? 'admin-created',
    targetLevel,
    sessionIdleMinutes: optionalNumber(e.SESSION_IDLE_MINUTES, 'SESSION_IDLE_MINUTES') ?? sessionDefaults.idle,
    sessionAbsoluteHours: optionalNumber(e.SESSION_ABSOLUTE_HOURS, 'SESSION_ABSOLUTE_HOURS') ?? sessionDefaults.absolute,
    sessionMaxConcurrent: optionalNumber(e.SESSION_MAX_CONCURRENT, 'SESSION_MAX_CONCURRENT') ?? sessionDefaults.max,
    fieldKeys,
    testMode,
    // Test mode stands a fake in for the daemon so the upload suite can prove both halves — that a file the
    // scanner calls bad is refused, and that an ordinary one is kept — on a machine with no daemon running.
    // An explicit MALWARE_SCANNER setting still wins, so the same suite can be pointed at a real clamd.
    malwareScanner:
      e.MALWARE_SCANNER === 'off'
        ? { kind: 'none' }
        : testMode && e.MALWARE_SCANNER === undefined
          ? { kind: 'test' }
          : e.CLAMD_SOCKET && e.CLAMD_SOCKET !== ''
            ? { kind: 'clamd', socketPath: e.CLAMD_SOCKET, timeoutMs: optionalNumber(e.CLAMD_TIMEOUT_MS, 'CLAMD_TIMEOUT_MS') ?? 30_000 }
            : {
                kind: 'clamd',
                host: e.CLAMD_HOST && e.CLAMD_HOST !== '' ? e.CLAMD_HOST : '127.0.0.1',
                port: optionalNumber(e.CLAMD_PORT, 'CLAMD_PORT') ?? 3310,
                timeoutMs: optionalNumber(e.CLAMD_TIMEOUT_MS, 'CLAMD_TIMEOUT_MS') ?? 30_000,
              },
    tlsEnabled: tlsMode !== 'off',
    roles,
    adminRole,
    features,
    design,
    outboundAllowedHosts: e.OUTBOUND_ALLOWED_HOSTS.split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
    // A preview is loopback-only plain http; anything else ignores the token, whatever .env says.
    previewMode: e.PREVIEW_SIGNIN_TOKEN.trim().length >= 32 && e.TLS_MODE === 'off' && !e.BIND_LAN,
    aiWebSearch: e.AI_ENABLED && e.AI_WEB_SEARCH,
    aiWebSearchDomains: e.AI_WEB_SEARCH_DOMAINS.split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
    retentionMonths: optionalNumber(e.RETENTION_MONTHS, 'RETENTION_MONTHS'),
    rateLimits: {
      // Test mode always raises the general limiter (contract §1.16) so a security suite that makes hundreds of
      // ordinary requests is not throttled; a value in .env must not reinstate the production limit here.
      generalPerMin: testMode ? generalDefault : (optionalNumber(e.RATE_LIMIT_GENERAL_PER_MIN, 'RATE_LIMIT_GENERAL_PER_MIN') ?? generalDefault),
      loginPerAccount: optionalNumber(e.RATE_LIMIT_LOGIN_PER_ACCOUNT, 'RATE_LIMIT_LOGIN_PER_ACCOUNT') ?? 5,
      loginPerIp: optionalNumber(e.RATE_LIMIT_LOGIN_PER_IP, 'RATE_LIMIT_LOGIN_PER_IP') ?? 20,
      mfaPerAccount: optionalNumber(e.RATE_LIMIT_MFA_PER_ACCOUNT, 'RATE_LIMIT_MFA_PER_ACCOUNT') ?? 5,
      registrationPerHour: optionalNumber(e.RATE_LIMIT_REGISTRATION_PER_HOUR, 'RATE_LIMIT_REGISTRATION_PER_HOUR') ?? 3,
      resetPerAccount: optionalNumber(e.RATE_LIMIT_RESET_PER_ACCOUNT, 'RATE_LIMIT_RESET_PER_ACCOUNT') ?? 3,
      resetPerIp: optionalNumber(e.RATE_LIMIT_RESET_PER_IP, 'RATE_LIMIT_RESET_PER_IP') ?? 10,
      aiPerHour: optionalNumber(e.RATE_LIMIT_AI_PER_HOUR, 'RATE_LIMIT_AI_PER_HOUR') ?? 20,
      uploadsPerHour: optionalNumber(e.RATE_LIMIT_UPLOADS_PER_HOUR, 'RATE_LIMIT_UPLOADS_PER_HOUR') ?? 20,
      apiKeyPerMin: optionalNumber(e.RATE_LIMIT_API_KEY_PER_MIN, 'RATE_LIMIT_API_KEY_PER_MIN') ?? 120,
    },
  };
  return Object.freeze(cfg);
}

/**
 * Loads the configuration once at import time. A configuration problem is printed as a plain message (never a
 * stack trace, never the secret value) and the process stops, so every entry point — server, scripts, tests —
 * behaves the same way.
 */
function loadConfigOrExit(): AppConfig {
  try {
    return loadConfig();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`\nThe app cannot start.\n${message}\n\n`);
    process.exit(1);
  }
}

export const config: AppConfig = loadConfigOrExit();
