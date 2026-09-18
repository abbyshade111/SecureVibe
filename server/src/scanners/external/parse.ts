/**
 * Mapping the JSON output of the optional external scanners into SecureVibe findings.
 *
 * Every finding keeps the tool's own rule id (prefixed `external.<tool>.`) and its message, because the point of
 * these tools is extra coverage: SecureVibe does not re-interpret what they found, it just presents it the same
 * way as everything else.
 */
import { createHash } from 'node:crypto';
import { relative, isAbsolute } from 'node:path';
import type { Finding, Severity } from '@shared/findings.js';

export type ExternalToolName = 'semgrep' | 'gitleaks' | 'trivy' | 'osv-scanner' | 'nano-analyzer';

/** Tools whose findings are one program's opinion rather than a rule that matched: never more than a suggestion. */
export const OPINION_TOOLS: ReadonlySet<ExternalToolName> = new Set<ExternalToolName>(['nano-analyzer']);

export interface ExternalFindingSeed {
  tool: ExternalToolName;
  ruleId: string;
  title: string;
  severity: Severity;
  file?: string;
  line?: number;
  snippet?: string;
  description: string;
  evidence: string;
  cwe: string[];
  references: string[];
  dependency?: Finding['dependency'];
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function relativeTo(appDir: string, file: string | undefined): string | undefined {
  if (!file) return undefined;
  const clean = isAbsolute(file) ? relative(appDir, file) : file;
  return clean.replace(/\\/g, '/').replace(/^\.\//, '');
}

const SEVERITY_WORDS: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  error: 'high',
  medium: 'medium',
  moderate: 'medium',
  warning: 'medium',
  low: 'low',
  info: 'info',
  informational: 'info',
  note: 'info',
  unknown: 'medium',
};

export function severityWord(value: string | undefined, fallback: Severity = 'medium'): Severity {
  if (!value) return fallback;
  return SEVERITY_WORDS[value.trim().toLowerCase()] ?? fallback;
}

// --- semgrep -------------------------------------------------------------------------------------

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: { cwe?: string[] | string; references?: string[]; owasp?: string[] | string };
  };
}

export function parseSemgrep(text: string, appDir: string): ExternalFindingSeed[] {
  let parsed: { results?: SemgrepResult[] };
  try {
    parsed = JSON.parse(text) as { results?: SemgrepResult[] };
  } catch {
    return [];
  }
  return (parsed.results ?? []).map((r) => {
    const cweRaw = r.extra?.metadata?.cwe;
    const cwe = (Array.isArray(cweRaw) ? cweRaw : cweRaw ? [cweRaw] : [])
      .map((c) => /CWE-\d+/.exec(c)?.[0])
      .filter((c): c is string => Boolean(c));
    const ruleId = r.check_id ?? 'rule';
    return {
      tool: 'semgrep' as const,
      ruleId,
      title: `Semgrep: ${ruleId.split('.').pop() ?? ruleId}`,
      severity: severityWord(r.extra?.severity),
      file: relativeTo(appDir, r.path),
      line: r.start?.line,
      snippet: r.extra?.lines?.trim().slice(0, 300),
      description: r.extra?.message ?? `Semgrep rule ${ruleId} matched.`,
      evidence: `Semgrep rule ${ruleId} matched${r.path ? ` in ${relativeTo(appDir, r.path)}` : ''}${r.start?.line ? ` at line ${r.start.line}` : ''}.`,
      cwe,
      references: r.extra?.metadata?.references ?? [],
    };
  });
}

// --- gitleaks ------------------------------------------------------------------------------------

interface GitleaksResult {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Match?: string;
  Entropy?: number;
}

export function parseGitleaks(text: string, appDir: string): ExternalFindingSeed[] {
  let parsed: GitleaksResult[] | { findings?: GitleaksResult[] };
  try {
    parsed = JSON.parse(text) as GitleaksResult[] | { findings?: GitleaksResult[] };
  } catch {
    return [];
  }
  const list: GitleaksResult[] = Array.isArray(parsed) ? parsed : (parsed.findings ?? []);
  return list.map((r) => {
    const ruleId = r.RuleID ?? 'secret';
    return {
      tool: 'gitleaks' as const,
      ruleId,
      title: `Possible secret in your code: ${r.Description ?? ruleId}`,
      severity: 'high' as Severity,
      file: relativeTo(appDir, r.File),
      line: r.StartLine,
      // The matched text is never copied into the report: it may be the secret itself.
      snippet: undefined,
      description: `Gitleaks matched its "${ruleId}" pattern here, which usually means a password, key or token was written into a file.`,
      evidence: `Gitleaks rule ${ruleId}${r.Entropy ? ` (entropy ${r.Entropy.toFixed(2)})` : ''} matched; the matched text is not reproduced here.`,
      cwe: ['CWE-798'],
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
    };
  });
}

// --- trivy ---------------------------------------------------------------------------------------

interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  CweIDs?: string[];
}

interface TrivyMisconfiguration {
  ID?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  Message?: string;
  PrimaryURL?: string;
}

interface TrivySecret {
  RuleID?: string;
  Title?: string;
  Severity?: string;
  StartLine?: number;
}

interface TrivyResult {
  Target?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
  Secrets?: TrivySecret[];
}

export function parseTrivy(text: string, appDir: string): ExternalFindingSeed[] {
  let parsed: { Results?: TrivyResult[] };
  try {
    parsed = JSON.parse(text) as { Results?: TrivyResult[] };
  } catch {
    return [];
  }
  const out: ExternalFindingSeed[] = [];
  for (const result of parsed.Results ?? []) {
    const target = relativeTo(appDir, result.Target);
    for (const v of result.Vulnerabilities ?? []) {
      out.push({
        tool: 'trivy',
        ruleId: v.VulnerabilityID ?? 'vulnerability',
        title: `${v.PkgName ?? 'A package'}: ${v.Title ?? v.VulnerabilityID ?? 'known vulnerability'}`,
        severity: severityWord(v.Severity),
        file: target,
        description: (v.Description ?? v.Title ?? '').slice(0, 800) || `Trivy reported ${v.VulnerabilityID} in ${v.PkgName}.`,
        evidence: `Trivy reported ${v.VulnerabilityID ?? 'a vulnerability'} in ${v.PkgName ?? 'a package'}@${v.InstalledVersion ?? '?'}${v.FixedVersion ? `; fixed in ${v.FixedVersion}` : ''}.`,
        cwe: v.CweIDs ?? [],
        references: v.PrimaryURL ? [v.PrimaryURL] : [],
        dependency: v.PkgName
          ? {
              package: v.PkgName,
              installedVersion: v.InstalledVersion ?? 'unknown',
              fixedVersion: v.FixedVersion,
              advisoryIds: v.VulnerabilityID ? [v.VulnerabilityID] : [],
              path: 'transitive',
              chain: [],
            }
          : undefined,
      });
    }
    for (const m of result.Misconfigurations ?? []) {
      out.push({
        tool: 'trivy',
        ruleId: m.ID ?? 'misconfiguration',
        title: `Trivy: ${m.Title ?? m.ID ?? 'configuration issue'}`,
        severity: severityWord(m.Severity),
        file: target,
        description: (m.Description ?? m.Message ?? '').slice(0, 800) || 'Trivy reported a configuration issue.',
        evidence: m.Message ?? `Trivy rule ${m.ID ?? ''} matched in ${target ?? 'the app folder'}.`,
        cwe: [],
        references: m.PrimaryURL ? [m.PrimaryURL] : [],
      });
    }
    for (const s of result.Secrets ?? []) {
      out.push({
        tool: 'trivy',
        ruleId: s.RuleID ?? 'secret',
        title: `Possible secret in your code: ${s.Title ?? s.RuleID ?? 'secret'}`,
        severity: severityWord(s.Severity, 'high'),
        file: target,
        line: s.StartLine,
        description: 'Trivy matched a pattern that usually means a password, key or token was written into a file.',
        evidence: `Trivy secret rule ${s.RuleID ?? ''} matched; the matched text is not reproduced here.`,
        cwe: ['CWE-798'],
        references: [],
      });
    }
  }
  return out;
}

// --- osv-scanner ---------------------------------------------------------------------------------

interface OsvVulnerability {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  severity?: { type?: string; score?: string }[];
}

interface OsvPackageResult {
  package?: { name?: string; version?: string; ecosystem?: string };
  vulnerabilities?: OsvVulnerability[];
}

export function parseOsvScanner(text: string, appDir: string): ExternalFindingSeed[] {
  let parsed: { results?: { source?: { path?: string }; packages?: OsvPackageResult[] }[] };
  try {
    parsed = JSON.parse(text) as typeof parsed;
  } catch {
    return [];
  }
  const out: ExternalFindingSeed[] = [];
  for (const result of parsed.results ?? []) {
    const file = relativeTo(appDir, result.source?.path);
    for (const pkg of result.packages ?? []) {
      for (const v of pkg.vulnerabilities ?? []) {
        out.push({
          tool: 'osv-scanner',
          ruleId: v.id ?? 'OSV',
          title: `${pkg.package?.name ?? 'A package'}: ${v.summary ?? v.id ?? 'known vulnerability'}`,
          severity: severityWord(v.database_specific?.severity),
          file,
          description: (v.summary ?? v.details ?? '').slice(0, 800) || `OSV reported ${v.id} for ${pkg.package?.name}.`,
          evidence: `osv-scanner reported ${[v.id, ...(v.aliases ?? [])].filter(Boolean).join(', ')} for ${pkg.package?.name ?? 'a package'}@${pkg.package?.version ?? '?'}.`,
          cwe: [],
          references: v.id ? [`https://osv.dev/vulnerability/${v.id}`] : [],
          dependency: pkg.package?.name
            ? {
                package: pkg.package.name,
                installedVersion: pkg.package.version ?? 'unknown',
                advisoryIds: [v.id, ...(v.aliases ?? [])].filter((id): id is string => Boolean(id)),
                path: 'transitive',
                chain: [],
              }
            : undefined,
        });
      }
    }
  }
  return out;
}

export const PARSERS: Record<ExternalToolName, (text: string, appDir: string) => ExternalFindingSeed[]> = {
  semgrep: parseSemgrep,
  gitleaks: parseGitleaks,
  trivy: parseTrivy,
  'osv-scanner': parseOsvScanner,
  // nano-analyzer writes a folder of documents rather than one JSON file; see nano-analyzer.ts.
  'nano-analyzer': () => [],
};

/** critical/high from an AI scanner become medium; lower levels stay as they are. */
function cappedOpinionSeverity(severity: Severity): Severity {
  return severity === 'critical' || severity === 'high' ? 'medium' : severity;
}

let counter = 0;

/** Tests only: make ids predictable. */
export function resetExternalCounter(): void {
  counter = 0;
}

export function toFinding(seed: ExternalFindingSeed, version?: string): Finding {
  counter += 1;
  const ruleId = `external.${seed.tool}.${seed.ruleId}`;
  return {
    id: `external-${String(counter).padStart(4, '0')}`,
    fingerprint: sha256(`external|${ruleId}|${seed.file ?? ''}|${seed.snippet ?? seed.line ?? seed.title}`),
    source: 'external',
    sourcesReporting: ['external'],
    ruleId,
    title: seed.title,
    // An unconfirmed opinion never counts as critical or high: those levels stop a build, and nothing here was
    // proved. The level the tool itself gave stays in severityBase and in the text, so nothing is hidden.
    severity: OPINION_TOOLS.has(seed.tool) ? cappedOpinionSeverity(seed.severity) : seed.severity,
    severityBase: seed.severity,
    priority: 'P3',
    exploitability: 'requires-network-exposure',
    // These tools are not tuned to the template's conventions, so their findings need a human look. An AI scanner's
    // findings are weaker still: nothing matched a rule and nothing was run, so they are always low confidence.
    confidence: OPINION_TOOLS.has(seed.tool) ? 'low' : 'medium',
    cwe: seed.cwe,
    location: seed.file ? { file: seed.file, line: seed.line, snippet: seed.snippet } : undefined,
    description: seed.description,
    impact: OPINION_TOOLS.has(seed.tool)
      ? `Suggested by ${seed.tool}, an experimental AI scanner you switched on. It read the code and formed an opinion: it did not run anything and nothing here is proof. It is known to report things that are not real, and it was built for a different kind of software, so a developer has to confirm this before you act on it. No part of your compliance report rests on it.`
      : `Reported by ${seed.tool}, an extra security scanner installed on this computer. SecureVibe includes it as-is; a developer should confirm whether it applies to your app.`,
    evidence: seed.evidence,
    remediation: {
      summary: OPINION_TOOLS.has(seed.tool)
        ? 'Have a developer check whether this is real before changing anything, then fix it or record why it is not a problem.'
        : `Read the ${seed.tool} rule "${seed.ruleId}" and apply its guidance, or record why it does not apply.`,
      steps: OPINION_TOOLS.has(seed.tool)
        ? [
            `Open ${seed.file ?? 'the file shown above'} and read what the scanner says it found.`,
            'Decide whether it is real. These suggestions are often wrong, so this step is the whole point.',
            'Fix it if it is real, or mark it as "not a problem" with a reason on the results page.',
          ]
        : [
            `Open the file shown above${seed.line ? ` at line ${seed.line}` : ''}.`,
            `Look up the ${seed.tool} rule "${seed.ruleId}" for what it checks.`,
            'Fix it, or mark it as "not a problem" with a reason on the results page.',
          ],
      references: seed.references,
    },
    verification: OPINION_TOOLS.has(seed.tool)
      ? { howToConfirmFixed: `Have a developer read the file and say whether this is real; if it is, fix it and run ${seed.tool} again.`, rerunCommand: `${seed.tool} (installed separately)` }
      : { howToConfirmFixed: `Run ${seed.tool} again; this rule no longer matches.`, rerunCommand: `${seed.tool} (installed separately)` },
    mappings: { asvs: [], aisvs: [], sbd: [] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'unknown',
    dependency: seed.dependency,
    tool: { name: seed.tool, version },
  };
}
