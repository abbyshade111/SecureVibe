/**
 * The AI review stage: Claude assesses the generated code against the applicable requirements.
 *
 * This is the weakest kind of evidence SecureVibe collects, so it is fenced hard (DESIGN §13 item 10):
 *  - reviews are batched per chapter, so each call sees a small, coherent set of requirements;
 *  - the model is given the exact text of the files, with a checksum per file;
 *  - every citation must quote a line that really is at the cited place *in the text that was sent*. A citation that
 *    does not match makes its assessment `not-verified` and is counted as a hallucination in the report.
 */
import type { DesignArtifacts } from '@shared/design.js';
import { type Confidence, type Finding, type Severity } from '@shared/findings.js';
import type { LlmUsage } from '@shared/pipeline.js';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { hashText } from '../audit.js';
import { addUsage, emptyLlmUsage, REQUIREMENTS_PER_CALL_BY_EFFORT } from '../budget.js';
import { aiReviewSystem, promptLibraryHash, wrapFile } from '../prompts/index.js';
import type { Budget, Effort, LlmProvider, SystemBlock, UsageDelta } from '../types.js';

/** One file exactly as it was hashed by the pipeline. */
export interface ReviewFile {
  path: string;
  sha256: string;
  content: string;
}

export interface RequirementForReview {
  id: string;
  description: string;
  level?: number;
  /** Plain-language explanation from the knowledge base, when there is one. */
  plain?: string;
}

export interface RequirementBatch {
  chapterId: string;
  chapterName: string;
  standard: 'asvs' | 'aisvs' | 'aisvs-appendix-c';
  requirements: RequirementForReview[];
}

export const MAX_FILE_CHARS = 60_000;
export const MAX_BATCH_CHARS = 400_000;
export const CITATION_LINE_TOLERANCE = 5;

export const AiReviewOutputSchema = z.strictObject({
  assessments: z
    .array(
      z.strictObject({
        requirementId: z.string().max(20),
        status: z.enum(['pass', 'fail', 'partial', 'not-applicable', 'unknown']),
        confidence: z.enum(['high', 'medium', 'low']),
        rationale: z.string().max(1500),
        citations: z
          .array(z.strictObject({ file: z.string().max(300), line: z.number().int(), snippet: z.string().max(400) }))
          .max(4),
      }),
    )
    .max(40),
  findings: z
    .array(
      z.strictObject({
        title: z.string().max(140),
        severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
        confidence: z.enum(['high', 'medium', 'low']),
        cwe: z.array(z.string().max(20)).max(4),
        file: z.string().max(300),
        line: z.number().int(),
        snippet: z.string().max(400),
        description: z.string().max(1000),
        impact: z.string().max(1000),
        evidence: z.string().max(1000),
        remediationSummary: z.string().max(500),
        remediationSteps: z.array(z.string().max(300)).max(8),
        requirementIds: z.array(z.string().max(20)).max(6),
      }),
    )
    .max(20),
});
export type AiReviewOutput = z.infer<typeof AiReviewOutputSchema>;

export type AiAssessmentStatus = 'pass' | 'fail' | 'partial' | 'not-applicable' | 'not-verified';

export interface AiCitation {
  file: string;
  line: number;
  snippet: string;
  verified: boolean;
}

export interface AiAssessment {
  id: string;
  status: AiAssessmentStatus;
  confidence: Confidence;
  rationale: string;
  citations: AiCitation[];
}

export interface AiReviewInput {
  appDir?: string;
  files: ReviewFile[];
  requirements: RequirementBatch[];
  design: DesignArtifacts;
  budget?: Budget;
  projectId?: string;
  runId?: string;
  effort?: Effort;
  abort?: AbortSignal;
  /** Called after each batch so the UI can show progress. */
  onBatch?(info: { chapterId: string; ok: boolean; message: string }): void;
}

export interface AiReviewOutcome {
  performed: boolean;
  model?: string;
  promptHash: string;
  assessments: AiAssessment[];
  findings: Finding[];
  /** Unverified citations ÷ all citations, over the whole review. 0 when there were no citations. */
  hallucinationRate: number;
  totalCitations: number;
  unverifiedCitations: number;
  /** Requirements whose call completed and was used (failed or skipped calls do not count). */
  reviewedRequirementIds: string[];
  /** One id per call made, as recorded in the AI audit log. */
  correlationIds: string[];
  usage: LlmUsage;
  batches: { chapterId: string; ok: boolean; message: string }[];
  skippedReason?: string;
}

export async function aiReview(provider: LlmProvider, input: AiReviewInput): Promise<AiReviewOutcome> {
  const usage = emptyLlmUsage(provider.name, provider.model);
  const sent = buildSentFiles(input.files);
  const manifest = fileManifest(input.files, sent);
  const promptHash = hashText(`${promptLibraryHash()}|${[...sent.keys()].sort().join(',')}`);
  const base: AiReviewOutcome = {
    performed: false,
    promptHash,
    assessments: [],
    findings: [],
    hallucinationRate: 0,
    totalCitations: 0,
    unverifiedCitations: 0,
    reviewedRequirementIds: [],
    correlationIds: [],
    usage,
    batches: [],
  };

  if (provider.name === 'null') {
    return { ...base, skippedReason: 'AI is not configured (preview mode)' };
  }

  const lineIndex = new Map<string, string[]>();
  for (const [path, content] of sent) lineIndex.set(path, content.split('\n'));

  let spentUsd = 0;
  let costliestCallUsd = 0;
  let servedModel: string | undefined;
  let findingSeq = 0;

  let part = 0;
  let stoppedFor: string | undefined;
  let consecutiveFailures = 0;
  for (const batch of splitBatches(input.requirements, requirementsPerCall(input.effort ?? 'low'))) {
    part++;
    if (input.abort?.aborted) {
      base.batches.push({ chapterId: batch.chapterId, ok: false, message: 'The review was cancelled.' });
      continue;
    }
    if (stoppedFor) {
      base.batches.push({ chapterId: batch.chapterId, ok: false, message: `Not reviewed: ${stoppedFor}` });
      continue;
    }
    // Each chapter is one call of about the same size, so the most expensive call so far predicts the next one;
    // stopping when that would cross the limit keeps the review under it instead of overshooting by a call.
    if (input.budget && spentUsd + costliestCallUsd > input.budget.maxUsd) {
      base.batches.push({
        chapterId: batch.chapterId,
        ok: false,
        message: 'The review stopped at the spending limit, so this chapter was not reviewed.',
      });
      continue;
    }

    const user = batchPrompt(batch, manifest, sent);
    const correlationId = `ai-review-${input.runId ?? 'run'}-${batch.chapterId}-${part}`;
    base.correlationIds.push(correlationId);
    const result = await provider.structured({
      purpose: 'ai-review',
      system: aiReviewSystem(input.design.securityContract),
      user,
      schema: AiReviewOutputSchema,
      // Reasoning shares the answer's token room, so reviews think briefly and get the largest allowed answer.
      effort: input.effort ?? 'low',
      maxTokens: 32_000,
      correlationId,
      projectId: input.projectId ?? 'unknown',
      ...(input.runId ? { runId: input.runId } : {}),
      ...(input.abort ? { abort: input.abort } : {}),
    });

    addUsage(usage, result.usage);
    spentUsd += result.usage.costUsd;
    costliestCallUsd = Math.max(costliestCallUsd, result.usage.costUsd);

    if (!result.ok) {
      base.batches.push({ chapterId: batch.chapterId, ok: false, message: result.message });
      input.onBatch?.({ chapterId: batch.chapterId, ok: false, message: result.message });
      // No credit or a rejected key: every further call would fail the same way, so the review stops here.
      if (result.accountProblem) stoppedFor = result.message;
      // Two failed calls in a row (outages, repeated cut-offs) also stop it, so money is not spent on a pattern.
      consecutiveFailures++;
      if (!stoppedFor && consecutiveFailures >= 2) stoppedFor = `two calls in a row failed (${result.message.replace(/\.$/, '')})`;
      continue;
    }
    servedModel = result.servedModel;
    base.performed = true;
    consecutiveFailures = 0;

    const asked = new Set(batch.requirements.map((r) => r.id));
    for (const a of result.data.assessments) {
      if (!asked.has(a.requirementId)) continue; // the model may only answer what it was asked
      const citations = a.citations.map((c) => ({
        file: c.file,
        line: c.line,
        snippet: c.snippet,
        verified: verifyCitation(lineIndex, c.file, c.line, c.snippet),
      }));
      base.totalCitations += citations.length;
      base.unverifiedCitations += citations.filter((c) => !c.verified).length;
      base.assessments.push(toAssessment(a, citations));
    }

    for (const f of result.data.findings) {
      const verified = verifyCitation(lineIndex, f.file, f.line, f.snippet);
      if (!verified) base.unverifiedCitations += 1;
      base.totalCitations += 1;
      findingSeq += 1;
      base.findings.push(toFinding(f, verified, findingSeq, input.runId));
    }

    const message = `Reviewed ${batch.requirements.length} requirements in ${batch.chapterName}.`;
    base.reviewedRequirementIds.push(...batch.requirements.map((r) => r.id));
    base.batches.push({ chapterId: batch.chapterId, ok: true, message });
    input.onBatch?.({ chapterId: batch.chapterId, ok: true, message });
  }

  base.hallucinationRate = base.totalCitations === 0 ? 0 : round4(base.unverifiedCitations / base.totalCitations);
  return { ...base, ...(servedModel ? { model: servedModel } : {}), usage };
}

/** The text actually sent to the model, per file. Citations are verified against exactly this. */
export function buildSentFiles(files: ReviewFile[]): Map<string, string> {
  const out = new Map<string, string>();
  let total = 0;
  for (const file of files) {
    if (total >= MAX_BATCH_CHARS) break;
    const room = Math.min(MAX_FILE_CHARS, MAX_BATCH_CHARS - total);
    const content = file.content.length > room ? file.content.slice(0, room) : file.content;
    out.set(file.path, content);
    total += content.length;
  }
  return out;
}

function fileManifest(files: ReviewFile[], sent: Map<string, string>): string {
  const rows = files
    .filter((f) => sent.has(f.path))
    .map((f) => {
      const content = sent.get(f.path)!;
      const cut = content.length < f.content.length ? ' (only the first part is shown)' : '';
      return `  ${f.path}  sha256=${f.sha256}  lines=${content.split('\n').length}${cut}`;
    });
  const missing = files.filter((f) => !sent.has(f.path)).map((f) => `  ${f.path} (not sent: the review was already full)`);
  return ['FILE MANIFEST', ...rows, ...missing].join('\n');
}

/**
 * The files go first as one cached block (identical for every call of a run), then the requirements of this call.
 * The files stay in the user turn, wrapped as untrusted data.
 */
function batchPrompt(batch: RequirementBatch, manifest: string, sent: Map<string, string>): SystemBlock[] {
  const files: string[] = [manifest, '', 'FILES'];
  for (const [path, content] of sent) files.push(wrapFile(path, content), '');
  const ask = [
    `CHAPTER ${batch.chapterId} — ${batch.chapterName} (${batch.standard.toUpperCase()})`,
    '',
    'REQUIREMENTS',
    ...batch.requirements.map(
      (r) => `  ${r.id}${r.level ? ` (level ${r.level})` : ''}: ${r.description}${r.plain ? `\n      in plain language: ${r.plain}` : ''}`,
    ),
    '',
    'Answer every requirement above, in order, using the files above. Copy each cited line exactly as it appears in',
    'the file, and give the line number counted from 1 at the top of that file.',
  ];
  return [
    { text: files.join('\n'), cache: true },
    { text: ask.join('\n') },
  ];
}

/**
 * Requirements per call: small enough that the answer always fits, so no call is wasted on a cut-off reply.
 * Reasoning shares the answer's token room, so a higher review effort gets fewer requirements per call.
 */
export const MAX_REQUIREMENTS_PER_CALL = 10;

export function requirementsPerCall(effort: Effort = 'low'): number {
  return Math.min(MAX_REQUIREMENTS_PER_CALL, REQUIREMENTS_PER_CALL_BY_EFFORT[effort] ?? MAX_REQUIREMENTS_PER_CALL);
}

export function splitBatches(batches: RequirementBatch[], perCall = MAX_REQUIREMENTS_PER_CALL): RequirementBatch[] {
  const out: RequirementBatch[] = [];
  for (const batch of batches) {
    for (let i = 0; i < batch.requirements.length; i += perCall) {
      out.push({ ...batch, requirements: batch.requirements.slice(i, i + perCall) });
    }
  }
  return out;
}

/** A citation is verified when the quoted text really appears within ±5 lines of the cited line. */
export function verifyCitation(lineIndex: Map<string, string[]>, file: string, line: number, snippet: string): boolean {
  const lines = lineIndex.get(file);
  if (!lines) return false;
  const needle = normalize(snippet);
  if (needle.length < 3) return false;
  const from = Math.max(0, line - 1 - CITATION_LINE_TOLERANCE);
  const to = Math.min(lines.length - 1, line - 1 + CITATION_LINE_TOLERANCE);
  if (from > to) return false;
  const window = normalize(lines.slice(from, to + 1).join('\n'));
  return window.includes(needle);
}

function normalize(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

function toAssessment(a: AiReviewOutput['assessments'][number], citations: AiCitation[]): AiAssessment {
  const needsCitation = a.status === 'pass' || a.status === 'partial' || a.status === 'fail';
  const anyVerified = citations.some((c) => c.verified);
  const status: AiAssessmentStatus =
    a.status === 'unknown' || (needsCitation && !anyVerified) ? 'not-verified' : (a.status as AiAssessmentStatus);
  const rationale =
    status === 'not-verified' && a.status !== 'unknown'
      ? `${a.rationale}\n\n(SecureVibe could not find the quoted code at the place the AI cited, so this answer is not counted.)`
      : a.rationale;
  return { id: a.requirementId, status, confidence: a.confidence, rationale, citations };
}

function toFinding(f: AiReviewOutput['findings'][number], verified: boolean, seq: number, runId?: string): Finding {
  const fingerprint = createHash('sha256')
    .update(['ai-review', 'ai-review.finding', f.file, normalize(f.snippet)].join('|'))
    .digest('hex');
  // An unverified citation means we could not confirm the code the model is describing: keep the finding, but say so
  // and lower its confidence, so it can never drive a requirement to "fail" or feed the automatic fix loop.
  const confidence: Confidence = verified ? f.confidence : 'low';
  return {
    id: `F-AI-${String(seq).padStart(4, '0')}`,
    fingerprint,
    source: 'ai-review',
    sourcesReporting: ['ai-review'],
    ruleId: 'ai-review.finding',
    title: f.title,
    severity: f.severity as Severity,
    severityBase: f.severity as Severity,
    priority: 'P3',
    exploitability: 'requires-network-exposure',
    confidence,
    cwe: f.cwe,
    location: { file: f.file, line: Math.max(1, f.line), snippet: f.snippet.slice(0, 2000) },
    description: f.description,
    impact: f.impact,
    evidence: verified
      ? f.evidence
      : `${f.evidence}\n\nSecureVibe could not find the quoted line at ${f.file}:${f.line}, so this finding is unconfirmed.`,
    remediation: { summary: f.remediationSummary, steps: f.remediationSteps, references: [] },
    mappings: {
      asvs: f.requirementIds.filter((id) => id.startsWith('V')),
      aisvs: f.requirementIds.filter((id) => id.startsWith('C') || id.startsWith('AC.')),
      sbd: [],
    },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'ai-generated',
    citationVerified: verified,
    ...(runId ? { firstSeenRun: runId, lastSeenRun: runId } : {}),
    tool: { name: 'claude-ai-review' },
  };
}

function round4(n: number): number {
  return Math.round(n * 10_000) / 10_000;
}

/** Converts the outcome into the shape the compliance engine consumes (server/src/compliance/types.ts). */
export function toAiReviewResult(outcome: AiReviewOutcome): {
  performed: boolean;
  model?: string;
  promptHash?: string;
  assessments: { requirementId: string; status: 'pass' | 'partial' | 'fail' | 'not-applicable' | 'unknown'; confidence: Confidence; rationale: string; citations: { file: string; line?: number; snippet?: string; verified: boolean }[] }[];
  reviewedRequirementIds?: string[];
  skippedReason?: string;
  unverifiedCitations?: number;
} {
  return {
    performed: outcome.performed,
    ...(outcome.model ? { model: outcome.model } : {}),
    promptHash: outcome.promptHash,
    assessments: outcome.assessments.map((a) => ({
      requirementId: a.id,
      status: a.status === 'not-verified' ? 'unknown' : a.status,
      confidence: a.confidence,
      rationale: a.rationale,
      citations: a.citations.map((c) => ({ file: c.file, line: c.line, snippet: c.snippet, verified: c.verified })),
    })),
    reviewedRequirementIds: outcome.reviewedRequirementIds,
    ...(outcome.skippedReason ? { skippedReason: outcome.skippedReason } : {}),
    unverifiedCitations: outcome.unverifiedCitations,
  };
}
