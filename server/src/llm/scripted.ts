/**
 * The scripted provider replays recorded, SDK-shaped model turns from JSON files. It exists so every failure mode —
 * refusals, truncation, malformed output, path escapes, prompt injection in a tool result, over-budget loops,
 * fallback models — is exercised by the test suite on a machine with no API key (DESIGN §13 item 13).
 *
 * It drives the same agent loop as the real provider, so the guard-rails under test are the production ones.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { auditCall, auditCallFrom, hashJson, hashText, storeExchange, type AuditOptions } from './audit.js';
import { costUsd, emptyLlmUsage } from './budget.js';
import { runAgentLoop, type AgentBlock, type AgentStopReason, type AgentTurn } from './agent-loop.js';
import { loadDefaultInjectionPatterns, screenText, type InjectionPatterns } from './screening.js';
import { emptyUsageDelta } from './types.js';
import type {
  AgentRunRequest,
  AgentRunResult,
  LlmProvider,
  LlmPurpose,
  ProviderName,
  StructuredRequest,
  StructuredResult,
  UsageDelta,
} from './types.js';

const ScriptedUsageSchema = z.object({
  input_tokens: z.number().default(0),
  output_tokens: z.number().default(0),
  cache_read_input_tokens: z.number().nullable().default(0),
  cache_creation_input_tokens: z.number().nullable().default(0),
  iterations: z
    .array(z.object({ type: z.string() }).loose())
    .nullable()
    .default(null),
});

const ScriptedContentSchema = z.union([
  z.object({ type: z.literal('text'), text: z.string() }),
  z.object({ type: z.literal('thinking'), thinking: z.string().default('') }).loose(),
  z.object({ type: z.literal('tool_use'), id: z.string(), name: z.string(), input: z.unknown() }),
]);

const ScriptedTurnSchema = z.object({
  id: z.string().default('msg_scripted'),
  role: z.literal('assistant').default('assistant'),
  model: z.string().optional(),
  stop_reason: z.enum(['end_turn', 'tool_use', 'max_tokens', 'refusal', 'pause_turn', 'stop_sequence']),
  stop_details: z.object({ type: z.string().default('refusal'), category: z.string().nullable().default(null), explanation: z.string().nullable().default(null) }).nullable().default(null),
  content: z.array(ScriptedContentSchema).default([]),
  usage: ScriptedUsageSchema.prefault({}),
  /** Simulates a transport failure instead of a reply. */
  error: z.object({ kind: z.string(), message: z.string() }).nullable().default(null),
});

export const ScenarioSchema = z.object({
  scenario: z.string(),
  description: z.string().default(''),
  model: z.string().default('claude-opus-5'),
  turns: z.array(ScriptedTurnSchema).min(1),
});
export type Scenario = z.infer<typeof ScenarioSchema>;
export type ScriptedTurn = z.infer<typeof ScriptedTurnSchema>;

export function loadScenarioFile(file: string): Scenario {
  const raw = JSON.parse(readFileSync(file, 'utf8')) as unknown;
  return ScenarioSchema.parse(raw);
}

export interface ScriptedOptions {
  /** Folder holding the scenario JSON files (settings.scriptedScenarioDir). */
  dir: string;
  /** Scenario used for every call, when set. */
  scenario?: string;
  /** Scenario per purpose; falls back to "<purpose>.json". */
  scenarioByPurpose?: Partial<Record<LlmPurpose, string>>;
  model?: string;
  injectionPatterns?: InjectionPatterns;
  /** Where the audit log goes; the scripted provider writes the same entries as the real one. */
  audit?: AuditOptions;
}

/** Replays scenario files. One provider instance walks one scenario from the first turn to the last. */
export class ScriptedProvider implements LlmProvider {
  readonly name: ProviderName = 'scripted';
  readonly model: string;
  private readonly cursors = new Map<string, number>();

  constructor(private readonly opts: ScriptedOptions) {
    this.model = opts.model ?? 'claude-opus-5';
  }

  private scenarioName(purpose: LlmPurpose): string {
    return this.opts.scenario ?? this.opts.scenarioByPurpose?.[purpose] ?? purpose;
  }

  /** Resolves and caches the scenario for a purpose. Throws a clear error when the fixture is missing. */
  loadScenario(purpose: LlmPurpose): Scenario {
    const name = this.scenarioName(purpose);
    const file = name.endsWith('.json') ? join(this.opts.dir, name) : join(this.opts.dir, `${name}.json`);
    if (!existsSync(file)) {
      throw new Error(`scripted provider: no scenario file at ${file} (purpose "${purpose}")`);
    }
    return loadScenarioFile(file);
  }

  private nextTurn(scenario: Scenario): ScriptedTurn {
    const at = this.cursors.get(scenario.scenario) ?? 0;
    const turn = scenario.turns[at] ?? scenario.turns[scenario.turns.length - 1]!;
    this.cursors.set(scenario.scenario, at + 1);
    return turn;
  }

  /** Restarts the scenario (used when one provider instance serves several independent calls in a test). */
  reset(): void {
    this.cursors.clear();
  }

  async structured<T>(req: StructuredRequest<T>): Promise<StructuredResult<T>> {
    let scenario: Scenario;
    try {
      scenario = this.loadScenario(req.purpose);
    } catch (err) {
      return { ok: false, reason: 'error', message: (err as Error).message, usage: emptyUsageDelta(this.model) };
    }
    const turn = this.nextTurn(scenario);
    const servedModel = turn.model ?? scenario.model;
    const usage = usageFrom(turn, servedModel, this.model);
    const promptHash = hashJson({ system: req.system, user: req.user });
    const responseHash = hashJson(turn.content);
    this.audit(req, usage, {
      stopReason: turn.error ? 'error' : turn.stop_reason,
      ...(turn.stop_details?.category ? { stopCategory: turn.stop_details.category } : {}),
      promptHash,
      responseHash,
      ...(turn.error ? { error: turn.error.message } : {}),
    });
    storeExchange(
      {
        correlationId: req.correlationId,
        projectId: req.projectId,
        ...(req.runId ? { runId: req.runId } : {}),
        purpose: req.purpose,
        prompt: { system: req.system, user: req.user },
        response: turn.content,
      },
      this.opts.audit ?? {},
    );

    if (turn.error) {
      return { ok: false, reason: 'error', message: `The AI could not be reached: ${turn.error.message}`, usage };
    }
    if (turn.stop_reason === 'refusal') {
      const category = turn.stop_details?.category ?? undefined;
      return {
        ok: false,
        reason: 'refusal',
        ...(category ? { category } : {}),
        message: refusalMessage(category),
        usage: { ...usage, refused: true },
      };
    }
    if (turn.stop_reason === 'max_tokens') {
      return { ok: false, reason: 'max_tokens', message: MAX_TOKENS_MESSAGE, usage };
    }

    const text = turn.content
      .filter((b): b is { type: 'text'; text: string } => b.type === 'text')
      .map((b) => b.text)
      .join('');
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(text);
    } catch {
      return { ok: false, reason: 'invalid_output', message: INVALID_OUTPUT_MESSAGE, usage };
    }
    const parsed = req.schema.safeParse(parsedJson);
    if (!parsed.success) {
      return { ok: false, reason: 'invalid_output', message: INVALID_OUTPUT_MESSAGE, usage };
    }
    return { ok: true, data: parsed.data, usage, servedModel };
  }

  async agentRun(req: AgentRunRequest): Promise<AgentRunResult> {
    let scenario: Scenario;
    try {
      scenario = this.loadScenario(req.purpose);
    } catch (err) {
      const message = (err as Error).message;
      req.onEvent({ type: 'stop', status: 'error', message });
      return {
        status: 'error',
        ok: false,
        message,
        usage: emptyLlmUsage(this.name, this.model),
        iterations: 0,
        servedModels: [],
        pathDenials: 0,
        injectionFlags: 0,
      };
    }
    const patterns = this.opts.injectionPatterns ?? loadDefaultInjectionPatterns();
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId ?? 'unknown', req.runId);
    return runAgentLoop(req, {
      provider: this.name,
      model: this.model,
      screen: (text) => screenText(text, patterns),
      onTurnAudit: (audit) =>
        auditCall(
          context,
          auditCallFrom(audit.usage, {
            stopReason: audit.stopReason,
            ...(audit.stopCategory ? { stopCategory: audit.stopCategory } : {}),
            promptHash: audit.promptHash ?? '',
            responseHash: audit.responseHash ?? '',
            injectionFlags: audit.injectionFlags,
            pathDenials: audit.pathDenials,
            iteration: audit.iteration,
            durationMs: audit.durationMs,
          }),
        ),
      onStop: (info) => {
        if (!info.budgetStop) return;
        auditCall(context, {
          servedModel: this.model,
          stopReason: 'budget',
          fallbackUsed: false,
          inputTokens: 0,
          outputTokens: 0,
          cacheRead: 0,
          cacheWrite: 0,
          costUsd: 0,
          promptHash: '',
          responseHash: '',
          budgetStop: info.budgetStop,
          iteration: info.iterations,
        });
      },
      runTurn: async ({ messages }) => {
        const turn = this.nextTurn(scenario);
        if (turn.error) throw new Error(turn.error.message);
        const servedModel = turn.model ?? scenario.model;
        const result: AgentTurn = {
          blocks: blocksFrom(turn),
          raw: turn.content,
          stopReason: stopReasonFrom(turn.stop_reason),
          usage: usageFrom(turn, servedModel, this.model),
          promptHash: hashText(`${hashJson(req.system)}:${messages.length}`),
          responseHash: hashJson(turn.content),
        };
        const category = turn.stop_details?.category;
        return category ? { ...result, stopCategory: category } : result;
      },
    });
  }

  private auditContext(
    purpose: LlmPurpose,
    correlationId: string,
    projectId: string,
    runId?: string,
  ): Parameters<typeof auditCall>[0] {
    return {
      provider: this.name,
      requestedModel: this.model,
      purpose,
      correlationId,
      projectId,
      ...(runId ? { runId } : {}),
      options: this.opts.audit ?? {},
    };
  }

  private audit(
    req: StructuredRequest<unknown>,
    usage: UsageDelta,
    rest: { stopReason: string; stopCategory?: string; promptHash: string; responseHash: string; error?: string },
  ): void {
    auditCall(this.auditContext(req.purpose, req.correlationId, req.projectId, req.runId), auditCallFrom(usage, rest));
  }
}

export const MAX_TOKENS_MESSAGE =
  'The AI ran out of room before it finished its answer, so SecureVibe did not use the half-finished result.';

export const INVALID_OUTPUT_MESSAGE =
  'The AI\'s answer did not have the shape SecureVibe expects, so it was not used. Trying again usually fixes this.';

export function refusalMessage(category?: string): string {
  const base = 'The AI declined this request, so this step was not done.';
  return category ? `${base} It gave the reason "${category}".` : base;
}

function stopReasonFrom(reason: ScriptedTurn['stop_reason']): AgentStopReason {
  switch (reason) {
    case 'end_turn':
    case 'tool_use':
    case 'max_tokens':
    case 'refusal':
    case 'pause_turn':
      return reason;
    default:
      return 'other';
  }
}

function blocksFrom(turn: ScriptedTurn): AgentBlock[] {
  const blocks: AgentBlock[] = [];
  for (const b of turn.content) {
    if (b.type === 'text') blocks.push({ type: 'text', text: b.text });
    else if (b.type === 'tool_use') blocks.push({ type: 'tool_use', id: b.id, name: b.name, input: b.input });
  }
  return blocks;
}

function usageFrom(turn: ScriptedTurn, servedModel: string, requestedModel: string): UsageDelta {
  const counts = {
    inputTokens: turn.usage.input_tokens,
    outputTokens: turn.usage.output_tokens,
    cacheReadTokens: turn.usage.cache_read_input_tokens ?? 0,
    cacheWriteTokens: turn.usage.cache_creation_input_tokens ?? 0,
  };
  const fallbackUsed =
    servedModel !== requestedModel || (turn.usage.iterations ?? []).some((i) => i.type === 'fallback_message');
  return {
    ...counts,
    costUsd: costUsd(servedModel, counts),
    servedModel,
    fallbackUsed,
    refused: turn.stop_reason === 'refusal',
  };
}
