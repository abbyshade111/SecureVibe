/**
 * LLM provider contract (CONTRACTS §9.1). Three providers implement it: `anthropic` (the real SDK),
 * `scripted` (replays fixture files; every failure mode is testable without a key) and `null` (preview mode).
 *
 * Everything the model returns is data: structured outputs are validated with zod, tool inputs are validated with
 * zod, file paths are confined by the tool layer, and free-form text is never executed.
 */
import type { ZodType } from 'zod';
import type { LlmUsage } from '@shared/pipeline.js';

export type ProviderName = 'anthropic' | 'null' | 'scripted';

export type LlmPurpose =
  | 'quick-infer'
  | 'peer-review'
  | 'refine'
  | 'plan'
  | 'threat-model'
  | 'generate'
  | 'fix'
  | 'ai-review'
  | 'classify'
  | 'summarize';

export type Effort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';

/** One system prompt block. `cache: true` puts a prompt-cache breakpoint on the block (stable content first). */
export interface SystemBlock {
  text: string;
  cache?: boolean;
}

/** Token usage and cost of one API call (or one agent turn), priced at the model that actually served it. */
export interface UsageDelta {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costUsd: number;
  servedModel: string;
  fallbackUsed: boolean;
  refused: boolean;
}

export function emptyUsageDelta(model: string): UsageDelta {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    costUsd: 0,
    servedModel: model,
    fallbackUsed: false,
    refused: false,
  };
}

export interface StructuredRequest<T> {
  purpose: LlmPurpose;
  system: SystemBlock[];
  /**
   * The user turn: plain text, or blocks where a block marked `cache` ends a reusable prefix (for example the
   * files a review sends with every chapter). Untrusted content belongs here, never in `system`.
   */
  user: string | SystemBlock[];
  /** Output schema. Use strict objects without defaults/optionals (nullable instead) so the JSON schema is exact. */
  schema: ZodType<T>;
  effort: Effort;
  maxTokens: number;
  correlationId: string;
  projectId: string;
  runId?: string;
  abort?: AbortSignal;
}

export type StructuredFailureReason = 'refusal' | 'max_tokens' | 'invalid_output' | 'budget' | 'error';

export type StructuredResult<T> =
  | { ok: true; data: T; usage: UsageDelta; servedModel: string }
  | {
      ok: false;
      reason: StructuredFailureReason;
      /** Refusal category from `stop_details` (e.g. "cyber"), when the model declined. */
      category?: string;
      /** Plain-language explanation for the person using SecureVibe. */
      message: string;
      /** The account cannot make calls right now (key rejected, no credit): further calls would fail too. */
      accountProblem?: boolean;
      usage: UsageDelta;
    };

export interface Budget {
  maxIterations: number;
  maxUsd: number;
  maxWallClockMs: number;
  maxOutputTokens: number;
}

export type AgentToolName = 'list_files' | 'read_file' | 'write_file' | 'delete_file' | 'run_checks' | 'done';

/** A security event raised by the tool layer (path denials, flagged tool results). */
export interface SecurityEvent {
  event: 'agent.path-denied' | 'agent.injection-flagged' | 'agent.tool-error';
  outcome: 'blocked' | 'flagged';
  detail: Record<string, unknown>;
}

export interface ToolResult {
  content: string;
  isError?: boolean;
  /** When set, the content came from outside SecureVibe (a file, a check's output) and is wrapped + screened. */
  untrustedSource?: string;
  securityEvent?: SecurityEvent;
}

export interface AgentTool {
  name: AgentToolName;
  description: string;
  inputSchema: ZodType;
  run(input: unknown): Promise<ToolResult>;
}

export type AgentRunStatus =
  | 'done'
  | 'refusal'
  | 'max_tokens'
  | 'budget'
  | 'aborted'
  | 'error'
  | 'skipped'
  | 'incomplete';

export type AgentEvent =
  | { type: 'turn'; iteration: number; at: string }
  | { type: 'text'; text: string }
  | { type: 'tool_use'; id: string; tool: string; input: unknown }
  | { type: 'tool_result'; id: string; tool: string; isError: boolean; preview: string }
  | { type: 'usage'; usage: LlmUsage; turnCostUsd: number; servedModel: string; fallbackUsed: boolean }
  | { type: 'security'; event: SecurityEvent['event']; outcome: SecurityEvent['outcome']; detail: Record<string, unknown> }
  | { type: 'stop'; status: AgentRunStatus; message: string };

export interface AgentRunRequest {
  purpose: 'generate' | 'fix';
  system: SystemBlock[];
  user: string;
  tools: AgentTool[];
  budget: Budget;
  correlationId: string;
  onEvent(e: AgentEvent): void;
  abort: AbortSignal;
  projectId?: string;
  runId?: string;
  effort?: Effort;
}

export interface AgentRunResult {
  status: AgentRunStatus;
  /** True only when the agent called `done`. */
  ok: boolean;
  /** Plain-language outcome for the person using SecureVibe. */
  message: string;
  /** Refusal category when status is `refusal`. */
  category?: string;
  usage: LlmUsage;
  iterations: number;
  servedModels: string[];
  /** The validated input of the `done` tool call, when the run finished. */
  doneInput?: unknown;
  pathDenials: number;
  injectionFlags: number;
  /** Which budget stopped the run ("iterations", "usd", "wall-clock", "output-tokens"). */
  budgetStop?: string;
}

export interface LlmProvider {
  readonly name: ProviderName;
  readonly model: string;
  structured<T>(req: StructuredRequest<T>): Promise<StructuredResult<T>>;
  agentRun(req: AgentRunRequest): Promise<AgentRunResult>;
}

/** Errors the providers raise from a single model turn; the agent loop decides what each kind means. */
export type LlmErrorKind = 'aborted' | 'auth' | 'billing' | 'rate-limit' | 'bad-request' | 'network' | 'api' | 'parse' | 'exhausted' | 'unknown';

export class LlmError extends Error {
  constructor(
    public readonly kind: LlmErrorKind,
    message: string,
  ) {
    super(message);
    this.name = 'LlmError';
  }
}
