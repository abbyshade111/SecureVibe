/**
 * `ai-review`: Claude assesses the generated code against the applicable requirements, batched per chapter, with
 * every citation verified against the exact file text that was sent (DESIGN §13 item 10). Skipped honestly when
 * AI is not configured.
 */
import { readFileSync } from 'node:fs';
import { compileIgnore, isIgnored } from '../../scanners/sast/files.js';
import type { StageResult } from '@shared/pipeline.js';
import { aiReview, DEFAULT_BUDGETS, mergeUsage, toAiReviewResult, type ReviewFile, type RequirementBatch, type RequirementForReview } from '../../integration.js';
import { listFiles, sha256File } from '../../generator/files.js';
import { MIN_STAGE_BUDGET_USD, budgetExhaustedText, finishStage, stageBudgetUsd, startStage } from '../stage-helpers.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { extensionOf, languageBreakdown, LANGUAGES } from '@shared/languages.js';
import { carryForwardReview } from '../diff-aware.js';
import type { PipelineCtx } from '../types.js';

const MAX_FILES = 250;

/**
 * What the review may read: every language listed in shared/languages.ts, whether or not SecureVibe's own rules
 * parse it, plus page templates and the few configuration files that say how an app is put together.
 *
 * Until 24 September 2026 this was TypeScript and EJS only. The review is the whole substance of "an app in
 * another language still gets a real check" (ADR-012), and on a Python app it reviewed 139 requirements and
 * cited nothing, twice, at twenty cents a time: not one .py file had been handed to it. The file selection was
 * the reason, not the model.
 */
const CODE_EXTENSIONS = new Set([...LANGUAGES.flatMap((l) => l.extensions), '.html', '.hbs', '.pug', '.vue', '.svelte']);
const CONFIG_FILES = /(^|\/)(package\.json|securevibe\.manifest\.json|requirements\.txt|pyproject\.toml|Pipfile|go\.mod|Cargo\.toml|Gemfile|composer\.json|Dockerfile|compose\.ya?ml|docker-compose\.ya?ml)$/;

/** Lower sorts first: security code, other source, views, configuration, then tests. Any language. */
export function reviewPriority(relPath: string): number {
  if (/\.(test|spec)\.[^/]+$/.test(relPath) || /(^|\/)(tests?|spec|__tests__)\//.test(relPath) || /(^|\/)test_[^/]+\.py$/.test(relPath)) return 4;
  if (/(^|\/)(security|auth|authz|login|session|permission)s?(\/|\.|_)/.test(relPath) || /(^|\/)(app|server|main|process|middleware|token|csrf|views|routes|api)\.[^/.]+$/.test(relPath)) return 0;
  if (CONFIG_FILES.test(relPath)) return 3;
  if (/\.(ejs|html|hbs|pug|vue|svelte)$/.test(relPath)) return 2;
  if (CODE_EXTENSIONS.has(extensionOf(relPath))) return 1;
  return 3;
}

/** The files the AI review may read: the scan's own exclusions apply, and only code, views and key config. */
export function collectFiles(appDir: string, extraIgnore: string[]): ReviewFile[] {
  const ignore = compileIgnore(extraIgnore);
  const files = listFiles(appDir)
    .filter((f) => !f.relPath.startsWith('node_modules/') && !isIgnored(f.relPath, ignore))
    .filter((f) => CODE_EXTENSIONS.has(extensionOf(f.relPath)) || CONFIG_FILES.test(f.relPath))
    .sort((a, b) => reviewPriority(a.relPath) - reviewPriority(b.relPath) || a.relPath.localeCompare(b.relPath));
  return files.slice(0, MAX_FILES).map((f) => {
    let content = '';
    try {
      content = readFileSync(f.absPath, 'utf8');
    } catch {
      content = '';
    }
    return { path: f.relPath, sha256: sha256File(f.absPath) ?? '', content };
  });
}

/**
 * What the review looks at first.
 *
 * The review is paid for by the call and stops when the money set aside for it runs out, so the order decides what
 * gets lost when it does. Three things decide it, in this order:
 *
 *  1. A chapter the automated scanners already found something in. There is evidence of trouble there, so a human
 *     reading of that code is worth more than anywhere else.
 *  2. How much goes wrong when that chapter is wrong. Somebody getting in as another person (authentication,
 *     authorization, sessions) or data being read or injected (validation, data protection) comes before how the
 *     code is arranged or what it writes to a log.
 *  3. Level 1 requirements before level 2, because the first level is the floor every app is meant to meet.
 *
 * Nothing is dropped from the list: this only decides what is reviewed first, so a review that stops early stops on
 * the least consequential part rather than wherever the alphabet happened to reach.
 */
const CHAPTER_RISK: Record<string, number> = {
  // Somebody getting in, or acting as somebody else.
  V6: 0, // Authentication
  V8: 0, // Authorization
  V7: 1, // Session Management
  V9: 1, // Self-contained Tokens
  V10: 1, // OAuth and OIDC
  // Data going somewhere it should not, or untrusted input being believed.
  V2: 2, // Validation and Business Logic
  V14: 2, // Data Protection
  V1: 3, // Encoding and Sanitization
  V5: 3, // File Handling
  V4: 3, // API and Web Service
  V3: 4, // Web Frontend Security
  V11: 4, // Cryptography
  V12: 4, // Secure Communication
  // How the app is put together and run.
  V13: 5, // Configuration
  V15: 6, // Secure Coding and Architecture
  V16: 6, // Security Logging and Error Handling
  V17: 7, // WebRTC
};
const DEFAULT_CHAPTER_RISK = 5;

/** Chapters the scanners already reported an open problem in, by requirement mapping and by finding source. */
function chaptersWithFindings(ctx: PipelineCtx): Set<string> {
  const out = new Set<string>();
  for (const finding of ctx.acc.findings) {
    if (finding.status !== 'open' && finding.status !== 'fix-attempted') continue;
    for (const id of [...(finding.mappings?.asvs ?? []), ...(finding.mappings?.aisvs ?? [])]) {
      const chapter = /^([A-Z]+\d+)\./.exec(id)?.[1];
      if (chapter) out.add(chapter);
    }
  }
  return out;
}

/** The order the batches are reviewed in; lower comes first. */
export function reviewOrder(batch: RequirementBatch, troubled: Set<string>): [number, number, number] {
  const risk = CHAPTER_RISK[batch.chapterId] ?? DEFAULT_CHAPTER_RISK;
  const lowestLevel = Math.min(...batch.requirements.map((r) => r.level ?? 1));
  return [troubled.has(batch.chapterId) ? 0 : 1, risk, lowestLevel];
}

function buildBatches(ctx: PipelineCtx): RequirementBatch[] {
  if (!ctx.design) return [];
  const applicability = ctx.design.applicability;
  const ids: { id: string; standard: 'asvs' | 'aisvs' | 'aisvs-appendix-c' }[] = [
    ...applicability.asvs.applicable.map((id) => ({ id, standard: 'asvs' as const })),
    ...(applicability.aisvs.enabled ? applicability.aisvs.applicable.map((id) => ({ id, standard: 'aisvs' as const })) : []),
    ...applicability.appendixC.applicable.map((id) => ({ id, standard: 'aisvs-appendix-c' as const })),
  ];
  const byChapter = new Map<string, RequirementBatch>();
  for (const { id, standard } of ids) {
    if (ctx.aiReviewSkip?.has(id)) continue;
    const frameworkStandard = standard === 'aisvs-appendix-c' ? 'aisvs' : standard;
    const info = ctx.frameworks.getRequirement(id);
    if (!info) continue;
    const key = `${standard}:${info.chapterId}`;
    let batch = byChapter.get(key);
    if (!batch) {
      batch = { chapterId: info.chapterId, chapterName: info.chapterName, standard, requirements: [] };
      byChapter.set(key, batch);
    }
    const plain = ctx.knowledge.requirementsPlain[id]?.plain;
    const req: RequirementForReview = { id: info.id, description: info.description, level: info.level, ...(plain ? { plain } : {}) };
    batch.requirements.push(req);
    void frameworkStandard;
  }
  // Highest-consequence first, so a review stopped by the spending limit loses the least (see reviewOrder).
  const troubled = chaptersWithFindings(ctx);
  return [...byChapter.values()].sort((a, b) => {
    const [ax, ay, az] = reviewOrder(a, troubled);
    const [bx, by, bz] = reviewOrder(b, troubled);
    return ax - bx || ay - by || az - bz || a.chapterId.localeCompare(b.chapterId);
  });
}

/** Why some requirements were not reviewed, in one short sentence (spending limit, cut-off or failed calls). */
function notReviewedNote(batches: { ok: boolean; message: string }[]): string {
  const failed = batches.filter((b) => !b.ok);
  if (failed.length === 0) return '';
  const limit = failed.filter((b) => /spending limit/.test(b.message)).length;
  const stopped = failed.filter((b) => b.message.startsWith('Not reviewed: '));
  const other = failed.length - limit - stopped.length;
  const parts = [
    ...(limit > 0 ? [`${limit} call(s) were not made because of the spending limit`] : []),
    ...(stopped.length > 0 ? [`${stopped.length} call(s) were not made: ${stopped[0]!.message.slice('Not reviewed: '.length).replace(/\.$/, '')}`] : []),
    ...(other > 0 ? [`${other} call(s) did not give a usable answer`] : []),
  ];
  return ` ${parts.join('; ')}.`;
}

/** The most recent finished run of this project that produced a compliance result, or nothing on a first build. */
function previousRunFor(ctx: PipelineCtx): PipelineRun | undefined {
  for (const id of ctx.store.listRunIds(ctx.project.id).filter((id) => id < ctx.run.id).reverse()) {
    const run = ctx.store.readRun(ctx.project.id, id);
    if (run?.compliance && run.provenance) return run;
  }
  return undefined;
}

export async function runAiReviewStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'ai-review');
  if (!ctx.design) {
    return finishStage(ctx, 'ai-review', 'skipped', 'The design was not available, so nothing could be reviewed.', started, { skippedReason: 'no design' });
  }
  const provider = ctx.providerFor('ai-review');
  if (provider.name === 'null') {
    return finishStage(ctx, 'ai-review', 'skipped', 'AI is not configured, so no AI review was performed. Nothing in this run was assessed by AI.', started, {
      skippedReason: 'AI is not configured (preview mode)',
    });
  }

  const files = collectFiles(ctx.appDir, ctx.extraIgnore ?? []);
  // "Cited 0 places" must be distinguishable from "was handed nothing": say up front what the review can read.
  const filesNote = `${files.length} file(s) were sent to the AI${files.length > 0 ? ` (${languageBreakdown(files.map((f) => f.path)).map((l) => `${l.language}: ${l.files}`).join(', ') || 'configuration only'})` : ''}.`;
  if (files.length === 0) {
    return finishStage(ctx, 'ai-review', 'skipped', 'No code the AI review can read was found in this app, so nothing was sent to the AI and nothing was assessed by it.', started, {
      skippedReason: 'no readable code files',
    });
  }

  /**
   * A rebuild usually changes a small part of an app. Verdicts the last check formed about files that are still
   * byte-for-byte the same are carried forward (see pipeline/diff-aware.ts), so the money goes on what changed.
   * Anything without a verified citation, or whose file has changed, is reviewed again.
   */
  const carried = carryForwardReview(previousRunFor(ctx), ctx.appDir, ctx.design.profileHash);
  if (carried.skip.size > 0) {
    ctx.aiReviewSkip = new Set([...(ctx.aiReviewSkip ?? []), ...carried.skip]);
    ctx.acc.evidence.push(...carried.evidence);
    ctx.log('ai-review', carried.note);
  }

  const requirements = buildBatches(ctx);
  if (requirements.length === 0) {
    const reason = ctx.design
      ? 'No requirements applied to this build, so there was nothing to review.'
      : 'The AI review reads the code against the rules that apply to this app, and which rules apply is not decided until the questions are answered. Nothing was sent to the AI and nothing was spent. Answer the questions and check again to get the review.';
    return finishStage(ctx, 'ai-review', 'skipped', reason, started, { skippedReason: ctx.design ? 'no applicable requirements' : 'questions not answered' });
  }

  const remaining = stageBudgetUsd(ctx, 'ai-review');
  if (remaining < MIN_STAGE_BUDGET_USD) {
    const reason = `Skipped because ${budgetExhaustedText(ctx)}. Nothing in this run was assessed by AI.`;
    return finishStage(ctx, 'ai-review', 'skipped', reason, started, { skippedReason: 'spending limit reached' });
  }

  const outcome = await aiReview(provider, {
    appDir: ctx.appDir,
    files,
    requirements,
    design: ctx.design,
    budget: { ...DEFAULT_BUDGETS.review, maxUsd: Math.min(DEFAULT_BUDGETS.review.maxUsd, remaining) },
    projectId: ctx.project.id,
    runId: ctx.run.id,
    ...(ctx.settings.reviewEffort ? { effort: ctx.settings.reviewEffort } : {}),
    abort: ctx.abort.signal,
    onBatch: (info) => ctx.bus.llm(`Reviewed ${info.chapterId}: ${info.message}`),
  });

  ctx.run.llmUsage = ctx.run.llmUsage ? mergeUsage(ctx.run.llmUsage, outcome.usage) : outcome.usage;
  ctx.bus.spend(ctx.run.llmUsage.estimatedCostUsd, ctx.run.llmUsage.calls);
  ctx.acc.findings.push(...outcome.findings);
  ctx.acc.correlationIds.push(...outcome.correlationIds);
  ctx.acc.servedModels.push(...(outcome.model ? [outcome.model] : []));

  ctx.aiReviewResult = toAiReviewResult(outcome);

  const requested = requirements.reduce((n, b) => n + b.requirements.length, 0);
  const alreadyVerified = (ctx.aiReviewSkip?.size ?? 0) - carried.skip.size;
  const skippedNote =
    (alreadyVerified > 0 ? `${alreadyVerified} requirement(s) already verified by automated checks were not sent to the AI (to save cost). ` : '') +
    (carried.note ? `${carried.note} ` : '');
  // Mostly unreviewed (spending limit, no credit, failed calls) is a warning, not a pass.
  const status = outcome.performed
    ? outcome.assessments.length > 0 && outcome.reviewedRequirementIds.length * 2 >= requested
      ? 'passed'
      : 'warning'
    : 'skipped';
  const summary = outcome.performed
    ? `${skippedNote}${filesNote} Claude reviewed ${outcome.reviewedRequirementIds.length} of ${requested} requirement(s) and cited ${outcome.totalCitations} place(s) in the code (${outcome.unverifiedCitations} citation(s) could not be verified).${notReviewedNote(outcome.batches)}`
    : (outcome.skippedReason ?? (ctx.abort.signal.aborted ? 'The AI review was stopped because the build was canceled; nothing it had started counts as evidence.' : 'The AI review did not run.'));
  return finishStage(ctx, 'ai-review', status, summary, started, {
    ...(outcome.skippedReason ? { skippedReason: outcome.skippedReason } : {}),
    details: { assessments: outcome.assessments.length, hallucinationRate: outcome.hallucinationRate, batches: outcome.batches },
  });
}
