/**
 * LLM audit log (AISVS C12.1, Appendix C AC.5.1): one JSON line per model call in <SECUREVIBE_HOME>/llm-audit.jsonl,
 * plus optional storage of the redacted prompt/response per correlation id. The API key is never part of any entry;
 * every string is passed through the secret redactor before it is written.
 */
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDeep } from './redaction.js';
import type { LlmPurpose, ProviderName, UsageDelta } from './types.js';

export interface AuditEntry {
  ts: string;
  correlationId: string;
  projectId: string;
  runId?: string;
  purpose: LlmPurpose;
  provider: ProviderName;
  requestedModel: string;
  servedModel: string;
  stopReason: string;
  stopCategory?: string;
  fallbackUsed: boolean;
  inputTokens: number;
  outputTokens: number;
  cacheRead: number;
  cacheWrite: number;
  costUsd: number;
  promptHash: string;
  responseHash: string;
  injectionFlags: number;
  pathDenials: number;
  budgetStop?: string;
  /** Agent runs write one entry per turn. */
  iteration?: number;
  durationMs?: number;
  error?: string;
}

export interface AuditOptions {
  /** SECUREVIBE_HOME. Default: env SECUREVIBE_HOME, else <repo>/workspace. */
  home?: string;
  storeFullPrompts?: boolean;
  /** Test hook: receives each JSON line instead of appending to the file. */
  write?: (line: string) => void;
}

export function resolveHome(home?: string): string {
  if (home) return resolve(home);
  if (process.env.SECUREVIBE_HOME) return resolve(process.env.SECUREVIBE_HOME);
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '../../../workspace');
}

export function auditFilePath(home?: string): string {
  return join(resolveHome(home), 'llm-audit.jsonl');
}

export function hashText(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function hashJson(value: unknown): string {
  return hashText(JSON.stringify(value) ?? 'null');
}

function safeSegment(id: string): string {
  const cleaned = id.replace(/[^A-Za-z0-9_-]/g, '_');
  return cleaned.length > 0 ? cleaned.slice(0, 120) : 'unknown';
}

/**
 * Identifiers SecureVibe generates itself. The entropy-based redactor mistakes long random ids for secrets, which
 * would make the log impossible to correlate, so these are kept when they have the expected shape.
 */
const TRUSTED_ID_FIELDS = ['correlationId', 'projectId', 'runId', 'promptHash', 'responseHash'] as const;
const TRUSTED_ID_SHAPE = /^[A-Za-z0-9_.-]{1,128}$/;

function trustedIds(entry: AuditEntry): Partial<AuditEntry> {
  const out: Record<string, string> = {};
  const record = entry as unknown as Record<string, unknown>;
  for (const field of TRUSTED_ID_FIELDS) {
    const value = record[field];
    if (typeof value === 'string' && TRUSTED_ID_SHAPE.test(value) && !value.startsWith('sk-')) out[field] = value;
  }
  return out as Partial<AuditEntry>;
}

/** Appends one redacted entry. Never throws: an audit failure must not break a build, it is reported on stderr. */
export function appendAudit(entry: AuditEntry, opts: AuditOptions = {}): void {
  const line = JSON.stringify({ ...redactDeep(entry), ...trustedIds(entry) });
  try {
    if (opts.write) {
      opts.write(line);
      return;
    }
    const file = auditFilePath(opts.home);
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, line + '\n', 'utf8');
  } catch (err) {
    process.stderr.write(`[securevibe] could not write llm audit entry: ${(err as Error).message}\n`);
  }
}

/** Everything about a call that does not change between its turns. */
export interface AuditContext {
  provider: ProviderName;
  requestedModel: string;
  purpose: LlmPurpose;
  correlationId: string;
  projectId: string;
  runId?: string;
  options?: AuditOptions;
}

/** What one model turn contributes to the audit log. */
export interface AuditCall {
  servedModel: string;
  stopReason: string;
  stopCategory?: string;
  fallbackUsed: boolean;
  inputTokens: number;
  outputTokens: number;
  cacheRead: number;
  cacheWrite: number;
  costUsd: number;
  promptHash: string;
  responseHash: string;
  injectionFlags?: number;
  pathDenials?: number;
  budgetStop?: string;
  iteration?: number;
  durationMs?: number;
  error?: string;
}

/** Fills the token and cost fields of an audit entry from one turn's usage. */
export function auditCallFrom(
  usage: UsageDelta,
  rest: Omit<AuditCall, 'servedModel' | 'fallbackUsed' | 'inputTokens' | 'outputTokens' | 'cacheRead' | 'cacheWrite' | 'costUsd'>,
): AuditCall {
  return {
    ...rest,
    servedModel: usage.servedModel,
    fallbackUsed: usage.fallbackUsed,
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    cacheRead: usage.cacheReadTokens,
    cacheWrite: usage.cacheWriteTokens,
    costUsd: usage.costUsd,
  };
}

/** Writes one audit line for one model turn. Called by every provider, for every call, success or not. */
export function auditCall(ctx: AuditContext, call: AuditCall): void {
  appendAudit(
    {
      ts: new Date().toISOString(),
      correlationId: ctx.correlationId,
      projectId: ctx.projectId,
      ...(ctx.runId ? { runId: ctx.runId } : {}),
      purpose: ctx.purpose,
      provider: ctx.provider,
      requestedModel: ctx.requestedModel,
      servedModel: call.servedModel,
      stopReason: call.stopReason,
      ...(call.stopCategory ? { stopCategory: call.stopCategory } : {}),
      fallbackUsed: call.fallbackUsed,
      inputTokens: call.inputTokens,
      outputTokens: call.outputTokens,
      cacheRead: call.cacheRead,
      cacheWrite: call.cacheWrite,
      costUsd: call.costUsd,
      promptHash: call.promptHash,
      responseHash: call.responseHash,
      injectionFlags: call.injectionFlags ?? 0,
      pathDenials: call.pathDenials ?? 0,
      ...(call.budgetStop ? { budgetStop: call.budgetStop } : {}),
      ...(call.iteration === undefined ? {} : { iteration: call.iteration }),
      ...(call.durationMs === undefined ? {} : { durationMs: call.durationMs }),
      ...(call.error ? { error: call.error } : {}),
    },
    ctx.options,
  );
}

export interface StoredExchange {
  correlationId: string;
  projectId: string;
  runId?: string;
  purpose: LlmPurpose;
  prompt: unknown;
  response: unknown;
}

/**
 * Stores the redacted prompt and response when `storeFullPrompts` is on:
 * `<home>/projects/<projectId>/pipeline/<runId>/llm/<correlationId>.json` (design-time calls without a run id go to
 * `<home>/projects/<projectId>/llm/`). Returns the path written, or undefined when storage is off or failed.
 */
export function storeExchange(exchange: StoredExchange, opts: AuditOptions = {}): string | undefined {
  if (!opts.storeFullPrompts) return undefined;
  try {
    const home = resolveHome(opts.home);
    const projectDir = join(home, 'projects', safeSegment(exchange.projectId));
    const dir = exchange.runId ? join(projectDir, 'pipeline', safeSegment(exchange.runId), 'llm') : join(projectDir, 'llm');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${safeSegment(exchange.correlationId)}.json`);
    const body = redactDeep({
      correlationId: exchange.correlationId,
      projectId: exchange.projectId,
      runId: exchange.runId,
      purpose: exchange.purpose,
      storedAt: new Date().toISOString(),
      prompt: exchange.prompt,
      response: exchange.response,
    });
    writeFileSync(file, JSON.stringify(body, null, 2), 'utf8');
    return file;
  } catch (err) {
    process.stderr.write(`[securevibe] could not store llm exchange: ${(err as Error).message}\n`);
    return undefined;
  }
}
