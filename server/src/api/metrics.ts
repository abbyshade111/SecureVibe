/**
 * `GET /api/metrics?days=7|30|90`: the Dashboard. Everything is counted from what SecureVibe already keeps on this
 * computer: the AI audit log (spending), the saved build runs (builds and open findings) and the security event log
 * (sign-ins and refused requests). Nothing is sent anywhere.
 */
import { closeSync, existsSync, openSync, readSync, statSync } from 'node:fs';
import { Router } from 'express';
import { MetricsResponseSchema, type MetricsResponse } from '@shared/api.js';
import { isOpen } from '@shared/findings.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { readSecurityEvents } from '../security/event-log.js';
import { validationError } from '../security/errors.js';
import type { ApiDeps } from './types.js';

const PERIODS = new Set([7, 30, 90]);
/** Only the most recent part of a very large audit log is read. */
const MAX_AUDIT_BYTES = 50 * 1024 * 1024;

const PURPOSE_LABELS: Record<string, string> = {
  generate: 'Writing the app',
  'ai-review': 'Reviewing the code',
  fix: 'Fixing findings',
  'peer-review': 'Second opinion on the design',
  refine: 'Follow-up questions about your idea',
  plan: 'Planning the build',
  'threat-model': 'Threat model',
  'quick-infer': 'Quick mode (reading your description)',
  summarize: 'Plain-language summaries',
  classify: 'Checking text for AI instructions',
  smoke: 'Connection test',
};

export const EVENT_LABELS: Record<string, string> = {
  'auth.token_accepted': 'Signed in with the startup link',
  'auth.token_rejected': 'Wrong startup link',
  'auth.token_rate_limited': 'Too many wrong startup links',
  'auth.denied': 'Request without a valid session',
  'csrf.rejected': 'Missing or wrong security token',
  'origin.blocked': 'Request from another website blocked',
  'access.denied': 'Access refused',
  'rate_limit.exceeded': 'Too many requests',
  'validation.rejected': 'Invalid input refused',
  'request.conflict': 'Conflicting request refused',
  'build.approved': 'Build approved',
  'build.approval_refused': 'Build without a valid approval refused',
};

const SIGN_IN_EVENTS = new Set(['auth.token_accepted']);
const NOT_REFUSALS = new Set(['auth.token_accepted', 'build.approved']);

interface AuditLine {
  ts?: string;
  projectId?: string;
  runId?: string;
  purpose?: string;
  provider?: string;
  servedModel?: string;
  requestedModel?: string;
  inputTokens?: number;
  outputTokens?: number;
  cacheRead?: number;
  cacheWrite?: number;
  costUsd?: number;
  error?: unknown;
}

function readTail(file: string): string {
  if (!existsSync(file)) return '';
  const size = statSync(file).size;
  const start = Math.max(0, size - MAX_AUDIT_BYTES);
  const fd = openSync(file, 'r');
  try {
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    const text = buf.toString('utf8');
    return start > 0 ? text.slice(text.indexOf('\n') + 1) : text;
  } finally {
    closeSync(fd);
  }
}

function readAudit(file: string, sinceMs: number): AuditLine[] {
  const out: AuditLine[] = [];
  for (const line of readTail(file).split('\n')) {
    if (!line) continue;
    try {
      const d = JSON.parse(line) as AuditLine;
      // Test runs use a scripted stand-in for the AI; they cost nothing and are not the owner's activity.
      if (d.provider === 'scripted') continue;
      if (d.ts && Date.parse(d.ts) >= sinceMs) out.push(d);
    } catch {
      // skip a damaged line
    }
  }
  return out;
}

const dayOf = (iso: string) => iso.slice(0, 10);
const round = (n: number, dp = 4) => Math.round(n * 10 ** dp) / 10 ** dp;

function days(from: Date, count: number): string[] {
  return Array.from({ length: count }, (_, i) => dayOf(new Date(from.getTime() + (i + 1) * 86_400_000).toISOString()));
}

function tally<T>(items: T[], key: (t: T) => string, usd?: (t: T) => number): Map<string, { count: number; usd: number }> {
  const m = new Map<string, { count: number; usd: number }>();
  for (const it of items) {
    const k = key(it);
    const e = m.get(k) ?? { count: 0, usd: 0 };
    e.count++;
    if (usd) e.usd += usd(it);
    m.set(k, e);
  }
  return m;
}

function toCounts(m: Map<string, { count: number; usd: number }>, label: (k: string) => string, withUsd: boolean) {
  return [...m.entries()]
    .map(([key, v]) => ({ key, label: label(key), count: v.count, ...(withUsd ? { usd: round(v.usd) } : {}) }))
    .sort((a, b) => (withUsd ? (b.usd ?? 0) - (a.usd ?? 0) : 0) || b.count - a.count);
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

export function computeMetrics(deps: Pick<ApiDeps, 'store' | 'config'>, period: number, now = new Date()): MetricsResponse {
  const fromDate = new Date(now.getTime() - period * 86_400_000);
  const sinceMs = fromDate.getTime();
  const projects = deps.store.list();
  const names = new Map(projects.map((p) => [p.id, p.name]));
  const appName = (id: string) => names.get(id) ?? (id === 'self-assessment' ? 'SecureVibe self-assessment' : 'Deleted app');

  // --- AI spending --------------------------------------------------------------------------------------------
  const audit = readAudit(deps.config.paths.auditLogFile, sinceMs);
  const cost = (a: AuditLine) => (typeof a.costUsd === 'number' ? a.costUsd : 0);
  const input = audit.reduce((n, a) => n + (a.inputTokens ?? 0), 0);
  const cacheRead = audit.reduce((n, a) => n + (a.cacheRead ?? 0), 0);
  const cacheWrite = audit.reduce((n, a) => n + (a.cacheWrite ?? 0), 0);
  const costByRun = new Map<string, number>();
  for (const a of audit) if (a.runId) costByRun.set(a.runId, (costByRun.get(a.runId) ?? 0) + cost(a));
  const aiByDay = tally(audit, (a) => dayOf(a.ts!), cost);

  // --- Builds ---------------------------------------------------------------------------------------------------
  const runs: { run: PipelineRun; appName: string }[] = [];
  for (const p of projects) {
    for (const runId of deps.store.listRunIds(p.id)) {
      const run = deps.store.readRun(p.id, runId);
      if (run && Date.parse(run.startedAt) >= sinceMs) runs.push({ run, appName: p.name });
    }
  }
  runs.sort((a, b) => b.run.startedAt.localeCompare(a.run.startedAt));
  const minutes = (r: PipelineRun) => (r.finishedAt ? (Date.parse(r.finishedAt) - Date.parse(r.startedAt)) / 60_000 : null);
  const finished = runs.map((r) => minutes(r.run)).filter((m): m is number => m !== null);
  // Cost per build: only builds that used AI (a build without AI costs nothing and would hide the real average).
  const buildCosts = runs.map((r) => costByRun.get(r.run.id) ?? 0).filter((c) => c > 0);

  // --- Security events ------------------------------------------------------------------------------------------
  const events = readSecurityEvents(deps.config.paths.securityEventsFile, sinceMs);
  const allEvents = readSecurityEvents(deps.config.paths.securityEventsFile, 0);
  const refusals = events.filter((e) => !NOT_REFUSALS.has(e.event));
  const signIns = events.filter((e) => SIGN_IN_EVENTS.has(e.event));
  const refusalsByDay = tally(refusals, (e) => dayOf(e.ts));
  const signInsByDay = tally(signIns, (e) => dayOf(e.ts));

  // --- Open findings (latest run of each app that is not archived) -----------------------------------------------
  const severityTally = new Map<string, { count: number; usd: number }>();
  for (const s of ['critical', 'high', 'medium', 'low', 'info']) severityTally.set(s, { count: 0, usd: 0 });
  const findingsByApp: MetricsResponse['findings']['byApp'] = [];
  for (const p of projects) {
    if (p.archivedAt || !p.lastRunId) continue;
    const open = (deps.store.readRun(p.id, p.lastRunId)?.findings ?? []).filter(isOpen);
    for (const f of open) severityTally.get(f.severity)!.count++;
    findingsByApp.push({
      projectId: p.id,
      appName: p.name,
      open: open.length,
      critical: open.filter((f) => f.severity === 'critical').length,
      high: open.filter((f) => f.severity === 'high').length,
    });
  }

  return MetricsResponseSchema.parse({
    days: period,
    from: fromDate.toISOString(),
    generatedAt: now.toISOString(),
    ai: {
      totalUsd: round(audit.reduce((n, a) => n + cost(a), 0)),
      calls: audit.length,
      failedCalls: audit.filter((a) => a.error !== undefined && a.error !== null).length,
      inputTokens: input + cacheRead + cacheWrite,
      outputTokens: audit.reduce((n, a) => n + (a.outputTokens ?? 0), 0),
      cacheShare: input + cacheRead + cacheWrite > 0 ? round(cacheRead / (input + cacheRead + cacheWrite), 3) : 0,
      byPurpose: toCounts(tally(audit, (a) => a.purpose ?? 'other', cost), (k) => PURPOSE_LABELS[k] ?? k, true),
      byApp: toCounts(tally(audit, (a) => a.projectId ?? 'unknown', cost), appName, true),
      byModel: toCounts(tally(audit, (a) => a.servedModel ?? a.requestedModel ?? 'unknown', cost), (k) => k, true),
      byDay: days(fromDate, period).map((day) => ({ day, usd: round(aiByDay.get(day)?.usd ?? 0), calls: aiByDay.get(day)?.count ?? 0 })),
    },
    builds: {
      total: runs.length,
      byStatus: toCounts(tally(runs, (r) => r.run.status), (k) => k, false),
      medianMinutes: finished.length ? round(median(finished)!, 1) : null,
      averageUsd: buildCosts.length ? round(buildCosts.reduce((a, b) => a + b, 0) / buildCosts.length, 2) : null,
      maxUsd: buildCosts.length ? round(Math.max(...buildCosts), 2) : null,
      recent: runs.slice(0, 15).map(({ run, appName: name }) => ({
        runId: run.id,
        projectId: run.projectId,
        appName: name,
        mode: run.mode,
        status: run.status,
        startedAt: run.startedAt,
        minutes: minutes(run) === null ? null : round(minutes(run)!, 1),
        usd: round(costByRun.get(run.id) ?? 0, 2),
        spendingCapUsd: run.spendingCapUsd,
        openFindings: (run.findings ?? []).filter(isOpen).length,
      })),
    },
    security: {
      signIns: signIns.length,
      refusals: refusals.length,
      lastSignInAt: signIns.at(-1)?.ts ?? null,
      byEvent: toCounts(tally(events, (e) => e.event), (k) => EVENT_LABELS[k] ?? k, false),
      byDay: days(fromDate, period).map((day) => ({ day, refusals: refusalsByDay.get(day)?.count ?? 0, signIns: signInsByDay.get(day)?.count ?? 0 })),
      recent: refusals
        .slice(-20)
        .reverse()
        .map((e) => ({
          ts: e.ts,
          event: e.event,
          label: EVENT_LABELS[e.event] ?? e.event,
          ...(e.method ? { method: e.method } : {}),
          ...(e.path ? { path: e.path } : {}),
          ...(e.status !== undefined ? { status: e.status } : {}),
        })),
      recordingSince: allEvents[0]?.ts ?? null,
    },
    findings: {
      open: toCounts(severityTally, (k) => k, false).sort((a, b) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(a.key) - ['critical', 'high', 'medium', 'low', 'info'].indexOf(b.key)),
      byApp: findingsByApp.sort((a, b) => b.critical - a.critical || b.high - a.high || b.open - a.open),
    },
  });
}

export function metricsRouter(deps: ApiDeps): Router {
  const router = Router();
  router.get('/metrics', (req, res) => {
    const period = Number(req.query['days'] ?? 30);
    if (!PERIODS.has(period)) throw validationError('Choose 7, 30 or 90 days.');
    res.json(computeMetrics(deps, period));
  });
  return router;
}
