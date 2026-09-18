/**
 * Building normalized Findings from scanner rules: stable fingerprints, remediation text from the
 * knowledge base (data/knowledge/remediation.json) with built-in fallbacks, and status/summary helpers.
 */
import type { Evidence } from '@shared/compliance.js';
import type {
  Confidence,
  Exploitability,
  Finding,
  FindingSource,
  Remediation,
  Severity,
} from '@shared/findings.js';
import type { RemediationEntry } from '@shared/knowledge.js';
import type { ScanContext, ScanStatus } from '../types.js';
import { sha256, type IntroducedBy } from './files.js';

/** Static description of a rule, shared by SAST, lint, secrets and config rules. */
export interface RuleMeta {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  asvs: string[];
  aisvs: string[];
  sbd?: string[];
  description: string;
  impact: string;
  remediation: Remediation;
  howToConfirmFixed?: string;
  exploitability: Exploitability;
  whoCanFix?: Finding['whoCanFix'];
}

export interface FindingInput {
  source: FindingSource;
  rule: RuleMeta;
  file?: string;
  line?: number;
  column?: number;
  endLine?: number;
  snippet?: string;
  endpoint?: string;
  evidence: string;
  severity?: Severity;
  confidence?: Confidence;
  introducedBy?: IntroducedBy;
  tool?: { name: string; version?: string };
  /** Extra text folded into the fingerprint when several findings share a file and snippet. */
  fingerprintExtra?: string;
}

export const RERUN_COMMAND = 'npm run verify -- <app folder>';

/** Collapses whitespace so that a reformatted line keeps the same fingerprint. */
export function normalizeSnippet(snippet: string): string {
  return snippet.replace(/\s+/g, ' ').trim().slice(0, 300);
}

export function fingerprintOf(source: string, ruleId: string, file: string | undefined, key: string): string {
  return sha256(`${source}|${ruleId}|${file ?? ''}|${normalizeSnippet(key)}`);
}

export function remediationFor(ctx: Pick<ScanContext, 'knowledge'>, ruleId: string): RemediationEntry | undefined {
  const table = ctx.knowledge?.remediation;
  if (!table) return undefined;
  return table[ruleId];
}

let counter = 0;

/** Builds a complete Finding for a rule hit. Ids are provisional; normalize.ts assigns the final F-nnnn ids. */
export function buildFinding(ctx: Pick<ScanContext, 'knowledge' | 'runId'>, input: FindingInput): Finding {
  const { rule } = input;
  const known = remediationFor(ctx, rule.id);
  const snippet = input.snippet ? normalizeSnippet(input.snippet) : undefined;
  const severity = input.severity ?? rule.severity;
  const key = input.fingerprintExtra
    ? `${snippet ?? input.endpoint ?? ''}|${input.fingerprintExtra}`
    : (snippet ?? input.endpoint ?? '');
  counter += 1;
  const location: Finding['location'] =
    input.file || input.endpoint
      ? {
          file: input.file,
          line: input.line,
          column: input.column,
          endLine: input.endLine,
          snippet,
          endpoint: input.endpoint,
        }
      : undefined;
  const howToConfirmFixed = known?.howToConfirmFixed ?? rule.howToConfirmFixed;
  return {
    id: `${input.source}-${String(counter).padStart(4, '0')}`,
    fingerprint: fingerprintOf(input.source, rule.id, input.file, key),
    source: input.source,
    sourcesReporting: [input.source],
    ruleId: rule.id,
    title: known?.title ?? rule.title,
    severity,
    severityBase: severity,
    priority: 'P3',
    exploitability: known?.exploitability ?? rule.exploitability,
    confidence: input.confidence ?? rule.confidence,
    cwe: unique([...rule.cwe, ...(known?.cwe ?? [])]),
    location,
    description: known?.description ?? rule.description,
    impact: known?.impact ?? rule.impact,
    evidence: input.evidence,
    remediation: known
      ? {
          summary: known.remediation.summary,
          steps: known.remediation.steps,
          example: known.remediation.example,
          references: known.remediation.references,
        }
      : rule.remediation,
    verification: howToConfirmFixed ? { howToConfirmFixed, rerunCommand: RERUN_COMMAND } : undefined,
    mappings: {
      asvs: unique([...rule.asvs, ...(known?.asvs ?? [])]),
      aisvs: unique([...rule.aisvs, ...(known?.aisvs ?? [])]),
      sbd: unique([...(rule.sbd ?? []), ...(known?.sbd ?? [])]),
    },
    status: 'open',
    whoCanFix: rule.whoCanFix ?? 'developer',
    introducedBy: input.introducedBy ?? 'unknown',
    tool: input.tool,
  };
}

export function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

let evidenceCounter = 0;

export function buildEvidence(
  input: Omit<Evidence, 'id' | 'tier'> & { tier?: Evidence['tier'] },
): Evidence {
  evidenceCounter += 1;
  return {
    id: `E-${input.type}-${String(evidenceCounter).padStart(4, '0')}`,
    tier: input.tier ?? (input.type === 'test' || input.type === 'dast' ? 'strong' : 'medium'),
    ...input,
  };
}

/** Stage status from the findings a scanner produced: high/critical fail the stage, anything else is a warning. */
export function statusFromFindings(findings: Finding[]): ScanStatus {
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'failed';
  if (findings.length > 0) return 'warning';
  return 'passed';
}

export function countBySeverityText(findings: Finding[]): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  const parts = (Object.keys(counts) as Severity[]).filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  return parts.length > 0 ? parts.join(', ') : 'none';
}

export function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

export function lineTextAt(text: string, line: number): string {
  const lines = text.split('\n');
  return (lines[line - 1] ?? '').trim();
}
