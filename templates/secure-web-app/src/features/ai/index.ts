/**
 * The AI assistant (contract §1.11). One page, one question at a time, and a fixed pipeline around every call:
 *
 *   kill switch → daily budget → input cleaning and screening → optional moderation → context from this
 *   person's own records → the model → shape, disclosure and identifier checks on the answer → logging and
 *   token accounting → the answer shown as plain text.
 *
 * Nothing on this page runs anything the model decided by itself: a change is only ever a proposal that the
 * person confirms, and the app then performs it through the ordinary repository function with that person's own
 * permissions.
 */
import { createHash } from 'node:crypto';
import type { Request, Response, Router } from 'express';
import { z } from 'zod';
import { config } from '../../config.ts';
import { HttpError, errors } from '../../lib/errors.ts';
import { aiRuntimeEnabled } from '../../lib/settings.ts';
import { renderPage } from '../../lib/views.ts';
import { queryAudit } from '../../security/audit.ts';
import { emit } from '../../security/events.ts';
import { defineRoute } from '../../security/routes.ts';
import { schemas } from '../../security/validate.ts';
import type { SessionUser } from '../auth/repo.ts';
import { AiUnavailableError, aiClient, unavailableMessage, type CompletionResult } from './client.ts';
import { actionsEnabled, assembleContext, dataScope, moderationEnabled, storesHistory } from './context.ts';
import { prepareInput } from './input.ts';
import { moderate } from './moderation.ts';
import { disclosesSystemPrompt, filterForUser, validateAnswer } from './output.ts';
import { FALLBACK_ANSWER, SYSTEM_PROMPT_HASH } from './prompt.ts';
import { screenForInjection } from './screening.ts';
import {
  appendHistory,
  clearHistory,
  createProposal,
  expireOldProposals,
  flaggedInteractionCount,
  getProposalForUser,
  historyForUser,
  interactionCount,
  markConfirmed,
  pendingProposalsForUser,
  recordInteraction,
  tokensUsedToday,
  usageByUser,
  usageTotals,
  type ProposalRow,
} from './repo.ts';
import { findTool, toolsFor, validateToolInput } from './tools.ts';

/** The message box. The length limit is enforced later so an over-long message is a 422, never a 400. */
const AskBody = z.strictObject({ message: z.string().max(200_000) });
const ProposalParams = z.strictObject({ id: schemas.id });
const ADMIN = `role:${config.adminRole}` as const;
const ENDPOINT = 'POST /ai';

// ---------------------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------------------

function assistantOn(): boolean {
  return aiRuntimeEnabled(config.AI_ENABLED);
}

const OFF_MESSAGE = 'The assistant is switched off at the moment. Everything else in the app works as usual.';

function sessionHash(req: Request): string {
  return req.session.logId ?? 'anonymous';
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function secondsUntilMidnightUtc(now: Date = new Date()): number {
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(60, Math.ceil((midnight - now.getTime()) / 1000));
}

interface ShownMessage {
  role: 'user' | 'assistant';
  text: string;
  at: string;
}

interface ShownProposal {
  id: string;
  summary: string;
  createdAt: string;
}

function shownProposals(rows: ProposalRow[]): ShownProposal[] {
  return rows.map((row) => ({ id: row.id, summary: row.summary, createdAt: row.created_at }));
}

/**
 * Everything the page shows passes the identifier filter first, including the person's own earlier messages —
 * so a record that belongs to somebody else cannot be reflected back through the assistant.
 */
function conversationFor(user: SessionUser): ShownMessage[] {
  if (!storesHistory()) return [];
  return historyForUser(user.id).map((row) => ({ role: row.role, text: filterForUser(row.content, user).text, at: row.created_at }));
}

function renderChat(
  req: Request,
  res: Response,
  extra: { answer?: string; question?: string; notice?: string; noticeType?: 'info' | 'error' } = {},
  status = 200,
): void {
  const user = req.user!;
  expireOldProposals();
  renderPage(
    req,
    res,
    'ai/index',
    {
      title: 'Assistant',
      enabled: assistantOn(),
      offMessage: OFF_MESSAGE,
      conversation: conversationFor(user),
      keepsHistory: storesHistory(),
      canPropose: actionsEnabled(),
      proposals: shownProposals(pendingProposalsForUser(user.id)),
      maxChars: config.AI_MAX_INPUT_CHARS,
      tokensToday: tokensUsedToday(user.id),
      dailyBudget: config.AI_USER_DAILY_TOKENS,
      dataScope: dataScope(),
      answer: extra.answer ?? '',
      // The question is shown back to the person; it passes the same identifier filter as the answer and the
      // history, so a reference to somebody else's record cannot be reflected off this page (AISVS C5.2.1).
      question: extra.question ? filterForUser(extra.question, user).text : '',
      notice: extra.notice ?? '',
      noticeType: extra.noticeType ?? 'info',
    },
    status,
  );
}

// ---------------------------------------------------------------------------------------------------------
// The request pipeline
// ---------------------------------------------------------------------------------------------------------

function rejectInput(req: Request, reason: string, message: string, status: 400 | 422, extra: Record<string, unknown> = {}): never {
  emit('ai.input.rejected', { req, reason, ...extra });
  throw new HttpError(status, 'validation_error', message);
}

async function ask(req: Request, res: Response): Promise<void> {
  const user = req.user!;
  if (!assistantOn()) throw errors.unavailable(OFF_MESSAGE);

  // 1. Daily token budget (checked before anything is sent, so an exhausted budget costs nothing).
  const budget = config.AI_USER_DAILY_TOKENS;
  const usedToday = tokensUsedToday(user.id);
  if (budget > 0 && usedToday >= budget) {
    emit('ai.budget.exceeded', { req, used: usedToday, budget });
    throw new HttpError(429, 'rate_limited', 'You have used your AI allowance for today. It starts again after midnight (UTC).', {
      retryAfterSeconds: secondsUntilMidnightUtc(),
    });
  }

  // 2. Cleaning and the character rules.
  const raw = (req.valid.body as { message: string }).message;
  const prepared = prepareInput(raw, config.AI_MAX_INPUT_CHARS);
  if (!prepared.ok) rejectInput(req, prepared.reason, prepared.message, prepared.status, prepared.detail ? { detail: prepared.detail } : {});
  const question = prepared.text;

  // 3. Prompt-injection screening: high-precision patterns block, the rest are recorded and allowed.
  const screening = screenForInjection(question);
  if (screening.decision === 'block') {
    rejectInput(req, 'injection', 'That message looks like an attempt to change how the assistant works, so it was not sent. Please rephrase it.', 400, {
      rule: screening.rule,
    });
  }
  const flagged = screening.decision === 'flag';
  if (flagged) emit('ai.input.flagged', { req, rule: screening.rule, source: 'question' });

  // 4. Optional moderation of the question.
  if (moderationEnabled()) {
    const decision = await moderate(req, 'input', question);
    if (!decision.allowed) {
      const message = decision.unavailable
        ? 'The safety check for messages is not available right now, so nothing was sent. Please try again in a moment.'
        : 'That message was not sent, because it looks like content this assistant does not handle.';
      rejectInput(req, decision.unavailable ? 'moderation-unavailable' : 'moderation', message, 400, decision.category ? { category: decision.category } : {});
    }
  }

  // 5. The context: instructions, this person's own records as untrusted data, their own history.
  const context = await assembleContext(user, question);
  for (const screened of context.screenedOut) {
    emit('ai.input.flagged', { req, rule: screened.rule, source: 'app-data', entity: screened.entity });
  }

  // 6. The model call itself.
  const client = aiClient();
  const toolNames = toolsFor(user, actionsEnabled()).map((tool) => tool.name);
  let completion: CompletionResult;
  try {
    completion = await client.complete({
      system: context.system,
      messages: context.messages,
      question,
      maxTokens: config.AI_MAX_OUTPUT_TOKENS,
      toolNames,
    });
  } catch (err) {
    if (err instanceof AiUnavailableError) throw errors.unavailable(unavailableMessage(err));
    throw err;
  }

  // 7. The answer: shape, length, disclosure, moderation, identifiers.
  let decision = 'allowed';
  let answerText = FALLBACK_ANSWER;
  let proposalId: string | undefined;

  if (completion.stopReason === 'refusal') {
    decision = 'refused';
    emit('ai.output.rejected', { req, reason: 'refusal' });
  } else {
    const validated = validateAnswer(completion.parsed);
    if (!validated.ok) {
      decision = validated.reason;
      emit('ai.output.rejected', { req, reason: validated.reason });
    } else if (disclosesSystemPrompt(validated.answer.answer)) {
      decision = 'system-prompt-disclosure';
      emit('ai.output.rejected', { req, reason: 'system-prompt-disclosure' });
    } else if (moderationEnabled() && !(await moderate(req, 'output', validated.answer.answer)).allowed) {
      decision = 'moderation';
      emit('ai.output.rejected', { req, reason: 'moderation' });
    } else {
      const filtered = filterForUser(validated.answer.answer, user);
      if (filtered.redactions > 0) {
        decision = 'filtered';
        emit('ai.output.rejected', { req, reason: 'inaccessible-records', redactions: filtered.redactions, outcome: 'blocked' });
      }
      answerText = filtered.text;
      // The sources come from the search results themselves, so what is shown cannot be invented (AISVS C7.4.1/C7.4.2).
      const sources = completion.sources ?? [];
      if (sources.length > 0) {
        answerText = `${answerText}\n\nSources the search used:\n${sources.map((s) => `- ${s.title} — ${s.url}`).join('\n')}`;
      }
    }
  }

  // 8. The record of what happened: the event, the interaction row and the token counters.
  const promptHash = sha256(`${context.system}\n${context.messages.map((m) => `${m.role}:${m.content}`).join('\n')}`);
  const responseHash = sha256(completion.raw);
  recordInteraction({
    userId: user.id,
    sessionHash: sessionHash(req),
    model: client.model,
    provider: client.provider,
    operation: 'chat',
    endpoint: ENDPOINT,
    inputTokens: completion.inputTokens,
    outputTokens: completion.outputTokens,
    promptHash,
    responseHash,
    injectionFlagged: flagged || context.screenedOut.length > 0,
    filterDecision: decision,
  });
  emit('ai.request', {
    req,
    model: client.model,
    provider: client.provider,
    operation: 'chat',
    inputTokens: completion.inputTokens,
    outputTokens: completion.outputTokens,
    promptHash,
    responseHash,
    systemPromptHash: SYSTEM_PROMPT_HASH,
    sessionHash: sessionHash(req),
    injectionFlagged: flagged,
    filterDecision: decision,
    stopReason: completion.stopReason,
  });

  // 9. A change the assistant suggests becomes a proposal. Nothing has happened yet.
  if (decision === 'allowed' && completion.proposal && actionsEnabled()) {
    const tool = findTool(completion.proposal.tool);
    if (!tool || !tool.mutates || !tool.available(user)) {
      emit('ai.output.rejected', { req, reason: 'unknown-tool', tool: completion.proposal.tool });
    } else {
      const checked = validateToolInput(tool, completion.proposal.input);
      if (!checked.ok) {
        emit('ai.output.rejected', { req, reason: 'tool-input-invalid', tool: tool.name, detail: checked.message });
      } else {
        proposalId = createProposal(user.id, tool.name, checked.input, tool.summarise(checked.input)).id;
      }
    }
  }

  // 10. Memory, when this app keeps one.
  if (storesHistory()) {
    appendHistory(user.id, 'user', question);
    appendHistory(user.id, 'assistant', answerText);
  }

  renderChat(req, res, {
    answer: answerText,
    question,
    notice: proposalId ? 'The assistant has suggested a change. Check it below and confirm it if you want it to happen.' : '',
  });
}

// ---------------------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------------------

export function register(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/ai', auth: 'user', summary: 'Ask the assistant' }, (req, res) => {
    renderChat(req, res, assistantOn() ? {} : { notice: OFF_MESSAGE }, assistantOn() ? 200 : 503);
  });

  defineRoute(
    router,
    { method: 'POST', path: '/ai', auth: 'user', rateLimit: 'ai', schema: { body: AskBody }, summary: 'Send a question to the assistant' },
    (req, res) => ask(req, res),
  );

  defineRoute(router, { method: 'POST', path: '/ai/reset', auth: 'user', rateLimit: 'ai', summary: 'Clear what the assistant remembers about you' }, (req, res) => {
    const removed = clearHistory(req.user!.id);
    req.session.flash('success', removed > 0 ? 'The assistant has forgotten your earlier messages.' : 'There was nothing for the assistant to forget.');
    res.redirect(303, '/ai');
  });

  defineRoute(
    router,
    { method: 'POST', path: '/ai/confirm/:id', auth: 'user', rateLimit: 'ai', schema: { params: ProposalParams }, summary: 'Confirm an action the assistant suggested' },
    async (req, res) => {
      if (!assistantOn()) throw errors.unavailable(OFF_MESSAGE);
      const user = req.user!;
      const { id } = req.valid.params as { id: string };
      expireOldProposals();
      // A proposal belongs to one person: for anybody else it simply does not exist.
      const proposal = getProposalForUser(id, user.id);
      if (!proposal) throw errors.notFound('That suggested action is no longer available.');
      if (proposal.status !== 'pending') throw errors.conflict('That suggested action was already dealt with.');

      const tool = findTool(proposal.tool);
      if (!tool || !tool.mutates || !tool.available(user)) throw errors.notFound('That suggested action is no longer available.');

      // The stored input is data like any other: it is checked against the schema again before anything runs.
      const checked = validateToolInput(tool, JSON.parse(proposal.input_json) as unknown);
      if (!checked.ok) {
        emit('ai.output.rejected', { req, reason: 'tool-input-invalid', tool: tool.name, detail: checked.message });
        throw new HttpError(422, 'validation_error', `That suggested action cannot be carried out: ${checked.message}`);
      }

      if (!markConfirmed(proposal.id, user.id, tool.summarise(checked.input))) {
        throw errors.conflict('That suggested action was already dealt with.');
      }
      try {
        // Carried out by the app, as this person, through the ordinary repository function.
        await tool.run(user, checked.input);
      } catch (err) {
        req.session.flash('error', err instanceof Error ? err.message : 'That action could not be carried out.');
        res.redirect(303, '/ai');
        return;
      }
      emit('ai.request', {
        req,
        model: aiClient().model,
        provider: aiClient().provider,
        operation: 'action.confirmed',
        inputTokens: 0,
        outputTokens: 0,
        promptHash: sha256(proposal.input_json),
        responseHash: sha256(proposal.id),
        tool: tool.name,
      });
      req.session.flash('success', 'Done — the change you confirmed has been made.');
      res.redirect(303, '/ai');
    },
  );

  defineRoute(router, { method: 'GET', path: '/admin/ai', auth: ADMIN, summary: 'AI assistant usage and controls' }, (req, res) => {
    renderPage(req, res, 'ai/admin', {
      title: 'AI assistant',
      enabled: assistantOn(),
      envEnabled: config.AI_ENABLED,
      model: config.AI_MODEL,
      provider: aiClient().provider,
      totals: usageTotals(),
      byUser: usageByUser(),
      interactions: interactionCount(),
      flagged: flaggedInteractionCount(),
      dailyBudget: config.AI_USER_DAILY_TOKENS,
      moderation: moderationEnabled(),
      keepsHistory: storesHistory(),
      canPropose: actionsEnabled(),
      dataScope: dataScope(),
      recentFlags: recentFlagEvents(),
    });
  });
}

/** The last inputs the screening refused or flagged — the rule that matched, never the text itself. */
function recentFlagEvents(): { ts: string; event: string; rule: string; userId: string | null }[] {
  const out: { ts: string; event: string; rule: string; userId: string | null }[] = [];
  for (const name of ['ai.input.rejected', 'ai.input.flagged'] as const) {
    for (const record of queryAudit({ event: name, limit: 10 })) {
      out.push({
        ts: record.ts,
        event: record.event,
        rule: String(record.fields.rule ?? record.fields.reason ?? '—'),
        userId: record.userId,
      });
    }
  }
  return out.sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, 15);
}
