/**
 * The owner's own AI-service keys (Settings → "Your AI service").
 *
 * A key typed in Settings is written to the `.env` file next to SecureVibe — the same place a key goes when you put
 * it there by hand — with the file made readable by its owner only. Keys are held in `process.env` for the running
 * process, so a new key works at once without a restart.
 *
 * Rules that hold everywhere: a key is never written to a log, a report, a project file or an AI prompt, and no API
 * ever returns one. The only things read back are which service is configured and the last four characters.
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const AI_SERVICES = ['anthropic', 'openai', 'google'] as const;
export type AiService = (typeof AI_SERVICES)[number];

export interface AiServiceInfo {
  id: AiService;
  label: string;
  envVar: string;
  /** SecureVibe can run builds with this service today. */
  usableForBuilds: boolean;
  /** Where the owner gets a key. */
  consoleUrl: string;
  /** What a key from this service looks like, for an early "that does not look right" check. */
  pattern: RegExp;
}

export const AI_SERVICE_INFO: Record<AiService, AiServiceInfo> = {
  anthropic: {
    id: 'anthropic',
    label: 'Anthropic (Claude)',
    envVar: 'ANTHROPIC_API_KEY',
    usableForBuilds: true,
    consoleUrl: 'https://console.anthropic.com/settings/keys',
    pattern: /^sk-ant-[A-Za-z0-9_-]{20,200}$/,
  },
  openai: {
    id: 'openai',
    label: 'OpenAI',
    envVar: 'OPENAI_API_KEY',
    usableForBuilds: false,
    consoleUrl: 'https://platform.openai.com/api-keys',
    pattern: /^sk-[A-Za-z0-9_-]{20,200}$/,
  },
  google: {
    id: 'google',
    label: 'Google (Gemini)',
    envVar: 'GOOGLE_API_KEY',
    usableForBuilds: false,
    consoleUrl: 'https://aistudio.google.com/app/apikey',
    pattern: /^[A-Za-z0-9_-]{20,200}$/,
  },
};

export interface KeyStatus {
  service: AiService;
  label: string;
  configured: boolean;
  /** Last four characters, so the owner can tell which key is in place. Never the key itself. */
  endsWith?: string;
  usableForBuilds: boolean;
  consoleUrl: string;
  /** True when the key came from the environment rather than the .env file (Settings cannot change it). */
  fromEnvironment?: boolean;
}

export class ApiKeyError extends Error {}

function envFile(repoRoot: string): string {
  return join(repoRoot, '.env');
}

/** Which services have a key right now, without revealing any of them. */
export function keyStatuses(repoRoot: string, env: NodeJS.ProcessEnv = process.env, fileKeys = readEnvFileKeys(repoRoot)): KeyStatus[] {
  return AI_SERVICES.map((id) => {
    const info = AI_SERVICE_INFO[id];
    const value = (env[info.envVar] ?? '').trim();
    const status: KeyStatus = {
      service: id,
      label: info.label,
      configured: value !== '',
      usableForBuilds: info.usableForBuilds,
      consoleUrl: info.consoleUrl,
    };
    if (value !== '') {
      status.endsWith = value.slice(-4);
      // A key that is set in the environment but not in the file was put there outside SecureVibe.
      if (fileKeys[info.envVar] === undefined) status.fromEnvironment = true;
    }
    return status;
  });
}

/** The AI keys currently written in the .env file (values are needed only to compare, never returned by an API). */
function readEnvFileKeys(repoRoot: string): Record<string, string> {
  const file = envFile(repoRoot);
  if (!existsSync(file)) return {};
  const out: Record<string, string> = {};
  for (const rawLine of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) {
      // A bare key pasted on its own line (SecureVibe has always accepted that for Anthropic).
      if (AI_SERVICE_INFO.anthropic.pattern.test(line)) out[AI_SERVICE_INFO.anthropic.envVar] = line;
      continue;
    }
    const key = line.slice(0, eq).trim();
    if (Object.values(AI_SERVICE_INFO).some((i) => i.envVar === key)) out[key] = line.slice(eq + 1).trim();
  }
  return out;
}

/** Replaces (or removes) one `KEY=value` line, leaving every other line and comment exactly as it was. */
function rewriteEnvFile(repoRoot: string, envVar: string, value: string | undefined): void {
  const file = envFile(repoRoot);
  const existing = existsSync(file) ? readFileSync(file, 'utf8') : '';
  const lines = existing === '' ? [] : existing.split(/\r?\n/);
  const isTarget = (line: string): boolean => {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) return false;
    if (trimmed.startsWith(`${envVar}=`)) return true;
    // The bare-key line form, for Anthropic only.
    return envVar === AI_SERVICE_INFO.anthropic.envVar && AI_SERVICE_INFO.anthropic.pattern.test(trimmed);
  };
  const kept = lines.filter((line) => !isTarget(line));
  // Removing a line can leave a blank tail; drop those so the file does not grow empty lines over time.
  while (kept.length > 0 && kept[kept.length - 1]!.trim() === '') kept.pop();
  if (value !== undefined) kept.push(`${envVar}=${value}`);
  // One trailing newline, no blank line pile-up.
  const text = `${kept.join('\n').replace(/\n+$/, '')}\n`;
  writeFileSync(file, text, { mode: 0o600 });
  chmodSync(file, 0o600);
}

/** Stores a key for one service. Returns the statuses afterwards; the key itself never leaves this module. */
export function setApiKey(repoRoot: string, service: AiService, key: string, env: NodeJS.ProcessEnv = process.env): KeyStatus[] {
  const info = AI_SERVICE_INFO[service];
  const trimmed = key.trim();
  if (trimmed === '') throw new ApiKeyError('Paste a key, or use Remove to take the current one out.');
  if (/\s/.test(trimmed)) throw new ApiKeyError('That does not look like a key: it contains a space or a line break.');
  if (!info.pattern.test(trimmed)) {
    throw new ApiKeyError(`That does not look like a ${info.label} key. Copy it again from ${info.consoleUrl}.`);
  }
  rewriteEnvFile(repoRoot, info.envVar, trimmed);
  env[info.envVar] = trimmed;
  return keyStatuses(repoRoot, env);
}

export function removeApiKey(repoRoot: string, service: AiService, env: NodeJS.ProcessEnv = process.env): KeyStatus[] {
  const info = AI_SERVICE_INFO[service];
  rewriteEnvFile(repoRoot, info.envVar, undefined);
  delete env[info.envVar];
  return keyStatuses(repoRoot, env);
}
