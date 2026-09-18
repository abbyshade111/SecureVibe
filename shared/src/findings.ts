/**
 * Normalized security finding, shared by every scanner, the AI review, the fix loop and the reports.
 *
 * Severity method: each source reports a base severity on a common scale (npm audit/OSV: CVSS-derived;
 * SAST/DAST/config: rule-defined). The pipeline then computes an adjusted severity from the deployment
 * context (e.g. an unauthenticated admin route matters less on a loopback-only app) and a priority
 * P1..P4 from (adjusted severity, confidence, exploitability). Both values are always shown.
 */
import { z } from 'zod';

export const FindingSourceSchema = z.enum([
  'sast',
  'lint',
  'semgrep',
  'secrets',
  'deps',
  'config',
  'dast',
  'tests',
  'ai-review',
  'external',
  'typecheck',
]);
export type FindingSource = z.infer<typeof FindingSourceSchema>;

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const ConfidenceSchema = z.enum(['high', 'medium', 'low']);
export type Confidence = z.infer<typeof ConfidenceSchema>;

export const PrioritySchema = z.enum(['P1', 'P2', 'P3', 'P4']);
export type Priority = z.infer<typeof PrioritySchema>;

export const ExploitabilitySchema = z.enum(['trivial', 'requires-auth', 'requires-network-exposure', 'theoretical']);
export type Exploitability = z.infer<typeof ExploitabilitySchema>;

export const FindingLocationSchema = z.object({
  file: z.string().optional(), // relative to the scanned app root
  line: z.number().int().positive().optional(),
  column: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  snippet: z.string().max(2000).optional(),
  /** For DAST / config findings that are not tied to a source line. */
  endpoint: z.string().optional(),
  requestExcerpt: z.string().max(2000).optional(),
  responseExcerpt: z.string().max(2000).optional(),
});
export type FindingLocation = z.infer<typeof FindingLocationSchema>;

export const RemediationSchema = z.object({
  summary: z.string(),
  steps: z.array(z.string()).default([]),
  example: z.string().optional(), // code example (plain text), in the project's conventions
  references: z.array(z.string()).default([]), // URLs
});
export type Remediation = z.infer<typeof RemediationSchema>;

export const FindingMappingsSchema = z.object({
  asvs: z.array(z.string()).default([]),
  aisvs: z.array(z.string()).default([]),
  sbd: z.array(z.string()).default([]),
});

export const FindingStatusSchema = z.enum(['open', 'fixed', 'fix-attempted', 'accepted', 'false-positive']);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const DependencyInfoSchema = z.object({
  package: z.string(),
  installedVersion: z.string(),
  fixedVersion: z.string().optional(),
  advisoryIds: z.array(z.string()).default([]), // GHSA-..., CVE-...
  path: z.enum(['direct', 'transitive', 'dev']),
  chain: z.array(z.string()).default([]),
  cvss: z.number().optional(),
});
export type DependencyInfo = z.infer<typeof DependencyInfoSchema>;

export const TriageSchema = z.object({
  reason: z.string(),
  by: z.string(),
  at: z.string(),
  expiresAt: z.string().optional(),
  compensatingControl: z.string().optional(),
  /** Plain-language consequence the person acknowledged when accepting. */
  acknowledgedConsequence: z.string().optional(),
});
export type Triage = z.infer<typeof TriageSchema>;

export const FindingSchema = z.object({
  id: z.string(), // unique within a run: "F-0001"
  fingerprint: z.string(), // stable across runs: sha256(source|ruleId|file|normalized snippet or endpoint)
  source: FindingSourceSchema,
  /** All sources that reported this same fingerprint (after de-duplication). */
  sourcesReporting: z.array(FindingSourceSchema).default([]),
  ruleId: z.string(),
  title: z.string(),
  severity: SeveritySchema, // adjusted severity (what the reports sort by)
  severityBase: SeveritySchema.optional(),
  adjustmentReason: z.string().optional(),
  priority: PrioritySchema.default('P3'),
  exploitability: ExploitabilitySchema.default('requires-network-exposure'),
  confidence: ConfidenceSchema,
  cwe: z.array(z.string()).default([]), // "CWE-79"
  location: FindingLocationSchema.optional(),
  description: z.string(), // what it is, plain language
  impact: z.string(), // why it matters
  evidence: z.string(), // what the tool observed
  remediation: RemediationSchema,
  verification: z
    .object({
      howToConfirmFixed: z.string(),
      rerunCommand: z.string().optional(),
      guardingTest: z.string().optional(),
    })
    .optional(),
  mappings: FindingMappingsSchema.default({ asvs: [], aisvs: [], sbd: [] }),
  status: FindingStatusSchema.default('open'),
  fixedInRound: z.number().int().optional(),
  fixDiffPath: z.string().optional(),
  fixNote: z.string().optional(),
  triage: TriageSchema.optional(),
  /** Who is expected to act on this. */
  whoCanFix: z.enum(['securevibe', 'developer', 'owner', 'hosting-provider']).default('developer'),
  introducedBy: z.enum(['template', 'ai-generated', 'ai-fixed', 'user', 'dependency', 'unknown']).default('unknown'),
  firstSeenRun: z.string().optional(),
  lastSeenRun: z.string().optional(),
  /** For AI-review findings: whether the cited verbatim snippet was found at the cited location. */
  citationVerified: z.boolean().optional(),
  dependency: DependencyInfoSchema.optional(),
  tool: z.object({ name: z.string(), version: z.string().optional() }).optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const PRIORITY_ORDER: Record<Priority, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

export function isOpen(f: Finding): boolean {
  return f.status === 'open' || f.status === 'fix-attempted';
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] ||
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.source.localeCompare(b.source) ||
      (a.location?.file ?? '').localeCompare(b.location?.file ?? '') ||
      (a.location?.line ?? 0) - (b.location?.line ?? 0),
  );
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) if (isOpen(f)) counts[f.severity]++;
  return counts;
}

export function countByPriority(findings: Finding[]): Record<Priority, number> {
  const counts: Record<Priority, number> = { P1: 0, P2: 0, P3: 0, P4: 0 };
  for (const f of findings) if (isOpen(f)) counts[f.priority]++;
  return counts;
}

/**
 * Priority rule (documented in the security report):
 *  P1: critical/high severity with high/medium confidence and exploitability trivial or requires-auth
 *  P2: high with low confidence, or medium with high confidence and trivial exploitability, or critical/high that needs network exposure
 *  P3: medium otherwise, low with high confidence
 *  P4: low otherwise, info
 */
export function computePriority(f: Pick<Finding, 'severity' | 'confidence' | 'exploitability'>): Priority {
  const { severity, confidence, exploitability } = f;
  const exposed = exploitability === 'trivial' || exploitability === 'requires-auth';
  if ((severity === 'critical' || severity === 'high') && confidence !== 'low' && exposed) return 'P1';
  if (severity === 'critical' || severity === 'high') return 'P2';
  if (severity === 'medium' && confidence === 'high' && exploitability === 'trivial') return 'P2';
  if (severity === 'medium') return 'P3';
  if (severity === 'low' && confidence === 'high') return 'P3';
  return 'P4';
}
