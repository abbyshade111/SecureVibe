/**
 * Everything the AI feature stores: what each model call cost (ai_interactions), the token counters the daily
 * budget is read from (ai_usage), the conversation memory that belongs to one person (ai_conversations) and the
 * actions waiting for that person's confirmation (ai_proposals).
 *
 * Every read is scoped by user_id. There is no function here that returns another person's rows.
 */
import { randomUUID } from 'node:crypto';
import { all, get, nowIso, run, withTransaction } from '../../db/index.ts';

export const HISTORY_TURNS = 10;
export const PROPOSAL_TTL_MINUTES = 30;

export interface InteractionInput {
  userId: string;
  sessionHash: string;
  model: string;
  provider: string;
  operation: string;
  endpoint: string;
  inputTokens: number;
  outputTokens: number;
  promptHash: string;
  responseHash: string;
  injectionFlagged: boolean;
  filterDecision: string;
}

export interface UsageRow {
  user_id: string | null;
  session_hash: string;
  endpoint: string;
  day: string;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  updated_at: string;
}

export interface ConversationRow {
  id: string;
  user_id: string;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
}

export interface ProposalRow {
  id: string;
  user_id: string;
  tool: string;
  input_json: string;
  summary: string;
  status: 'pending' | 'confirmed' | 'canceled' | 'expired';
  created_at: string;
  expires_at: string;
  confirmed_at: string | null;
  result_summary: string | null;
}

export function today(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------------------------------------
// Interactions and token counters
// ---------------------------------------------------------------------------------------------------------

/** One row per model call, plus the matching counters, written together so the two can never disagree. */
export function recordInteraction(input: InteractionInput): string {
  const id = randomUUID();
  const now = nowIso();
  withTransaction(() => {
    run(
      `INSERT INTO ai_interactions
         (id, user_id, session_hash, model, provider, operation, endpoint, input_tokens, output_tokens,
          prompt_hash, response_hash, injection_flagged, filter_decision, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        input.userId,
        input.sessionHash,
        input.model,
        input.provider,
        input.operation,
        input.endpoint,
        input.inputTokens,
        input.outputTokens,
        input.promptHash,
        input.responseHash,
        input.injectionFlagged ? 1 : 0,
        input.filterDecision,
        now,
      ],
    );
    addUsage(input.userId, input.sessionHash, input.endpoint, input.inputTokens, input.outputTokens, now);
  });
  return id;
}

/** Adds one request to the per user / session / endpoint counters for today. */
export function addUsage(
  userId: string,
  sessionHash: string,
  endpoint: string,
  inputTokens: number,
  outputTokens: number,
  now: string = nowIso(),
): void {
  run(
    `INSERT INTO ai_usage (id, user_id, session_hash, endpoint, day, requests, input_tokens, output_tokens, total_tokens, updated_at)
     VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
     ON CONFLICT (user_id, session_hash, endpoint, day) DO UPDATE SET
       requests = requests + 1,
       input_tokens = input_tokens + excluded.input_tokens,
       output_tokens = output_tokens + excluded.output_tokens,
       total_tokens = total_tokens + excluded.total_tokens,
       updated_at = excluded.updated_at`,
    [randomUUID(), userId, sessionHash, endpoint, today(new Date(now)), inputTokens, outputTokens, inputTokens + outputTokens, now],
  );
}

/** Tokens this person has used today, across all their sessions and endpoints. */
export function tokensUsedToday(userId: string, day: string = today()): number {
  return Number(get<{ total: number | null }>('SELECT SUM(total_tokens) AS total FROM ai_usage WHERE user_id = ? AND day = ?', [userId, day])?.total ?? 0);
}

export function usageForUser(userId: string, day: string = today()): UsageRow[] {
  return all<UsageRow>('SELECT * FROM ai_usage WHERE user_id = ? AND day = ? ORDER BY endpoint', [userId, day]);
}

// ---------------------------------------------------------------------------------------------------------
// Administration views (counters only — never the text of anybody's question)
// ---------------------------------------------------------------------------------------------------------

export interface UsageTotals {
  requests: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  people: number;
}

export function usageTotals(day: string = today()): UsageTotals {
  const row = get<{ requests: number | null; input_tokens: number | null; output_tokens: number | null; total_tokens: number | null; people: number | null }>(
    `SELECT SUM(requests) AS requests, SUM(input_tokens) AS input_tokens, SUM(output_tokens) AS output_tokens,
            SUM(total_tokens) AS total_tokens, COUNT(DISTINCT user_id) AS people
     FROM ai_usage WHERE day = ?`,
    [day],
  );
  return {
    requests: Number(row?.requests ?? 0),
    inputTokens: Number(row?.input_tokens ?? 0),
    outputTokens: Number(row?.output_tokens ?? 0),
    totalTokens: Number(row?.total_tokens ?? 0),
    people: Number(row?.people ?? 0),
  };
}

export interface UsageByUser {
  userId: string | null;
  email: string | null;
  requests: number;
  totalTokens: number;
}

export function usageByUser(day: string = today(), limit = 20): UsageByUser[] {
  return all<{ user_id: string | null; email: string | null; requests: number; total_tokens: number }>(
    `SELECT u.user_id AS user_id, users.email AS email, SUM(u.requests) AS requests, SUM(u.total_tokens) AS total_tokens
     FROM ai_usage u LEFT JOIN users ON users.id = u.user_id
     WHERE u.day = ?
     GROUP BY u.user_id, users.email
     ORDER BY total_tokens DESC
     LIMIT ?`,
    [day, limit],
  ).map((r) => ({ userId: r.user_id, email: r.email, requests: Number(r.requests), totalTokens: Number(r.total_tokens) }));
}

export function flaggedInteractionCount(): number {
  return Number(get<{ n: number }>('SELECT COUNT(*) AS n FROM ai_interactions WHERE injection_flagged = 1')?.n ?? 0);
}

export function interactionCount(): number {
  return Number(get<{ n: number }>('SELECT COUNT(*) AS n FROM ai_interactions')?.n ?? 0);
}

// ---------------------------------------------------------------------------------------------------------
// Conversation memory
// ---------------------------------------------------------------------------------------------------------

/** Oldest first, newest last, at most `turns` messages — always only this person's own rows. */
export function historyForUser(userId: string, turns: number = HISTORY_TURNS * 2): ConversationRow[] {
  return all<ConversationRow>('SELECT * FROM ai_conversations WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?', [userId, turns]).reverse();
}

export function appendHistory(userId: string, role: 'user' | 'assistant', content: string): void {
  run('INSERT INTO ai_conversations (id, user_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)', [randomUUID(), userId, role, content, nowIso()]);
}

export function clearHistory(userId: string): number {
  return run('DELETE FROM ai_conversations WHERE user_id = ?', [userId]).changes;
}

// ---------------------------------------------------------------------------------------------------------
// Proposed actions
// ---------------------------------------------------------------------------------------------------------

export function createProposal(userId: string, tool: string, input: unknown, summary: string): ProposalRow {
  const id = randomUUID();
  const now = new Date();
  run('INSERT INTO ai_proposals (id, user_id, tool, input_json, summary, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [
    id,
    userId,
    tool,
    JSON.stringify(input ?? null),
    summary,
    'pending',
    now.toISOString(),
    new Date(now.getTime() + PROPOSAL_TTL_MINUTES * 60_000).toISOString(),
  ]);
  const row = getProposalForUser(id, userId);
  if (!row) throw new Error('The proposed action could not be stored.');
  return row;
}

/** A proposal can only ever be read by the person it was made for. */
export function getProposalForUser(id: string, userId: string): ProposalRow | undefined {
  return get<ProposalRow>('SELECT * FROM ai_proposals WHERE id = ? AND user_id = ?', [id, userId]);
}

export function pendingProposalsForUser(userId: string): ProposalRow[] {
  return all<ProposalRow>("SELECT * FROM ai_proposals WHERE user_id = ? AND status = 'pending' AND expires_at > ? ORDER BY created_at DESC LIMIT 10", [
    userId,
    nowIso(),
  ]);
}

/**
 * Marks the proposal as confirmed. Returns false when it was already used, canceled or has expired, so a
 * proposal can never be carried out twice.
 */
export function markConfirmed(id: string, userId: string, resultSummary: string): boolean {
  const changes = run("UPDATE ai_proposals SET status = 'confirmed', confirmed_at = ?, result_summary = ? WHERE id = ? AND user_id = ? AND status = 'pending' AND expires_at > ?", [
    nowIso(),
    resultSummary,
    id,
    userId,
    nowIso(),
  ]).changes;
  return changes === 1;
}

export function cancelProposal(id: string, userId: string): boolean {
  return run("UPDATE ai_proposals SET status = 'canceled' WHERE id = ? AND user_id = ? AND status = 'pending'", [id, userId]).changes === 1;
}

export function expireOldProposals(): void {
  run("UPDATE ai_proposals SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?", [nowIso()]);
}

// ---------------------------------------------------------------------------------------------------------
// Account export and deletion (the account feature calls these through the entity registry)
// ---------------------------------------------------------------------------------------------------------

export function exportForUser(userId: string): { conversations: { role: string; text: string; at: string }[]; usage: UsageRow[] } {
  return {
    conversations: all<ConversationRow>('SELECT * FROM ai_conversations WHERE user_id = ? ORDER BY created_at', [userId]).map((r) => ({
      role: r.role,
      text: r.content,
      at: r.created_at,
    })),
    usage: all<UsageRow>('SELECT * FROM ai_usage WHERE user_id = ? ORDER BY day DESC LIMIT 400', [userId]),
  };
}

/** Removes this person's assistant data. The counters keep the totals but lose the link to the person. */
export function deleteForUser(userId: string): void {
  withTransaction(() => {
    run('DELETE FROM ai_conversations WHERE user_id = ?', [userId]);
    run('DELETE FROM ai_proposals WHERE user_id = ?', [userId]);
    run('UPDATE ai_usage SET user_id = NULL WHERE user_id = ?', [userId]);
    run('UPDATE ai_interactions SET user_id = NULL WHERE user_id = ?', [userId]);
  });
}
