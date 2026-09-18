/** findings.sarif: a minimal, structurally valid SARIF 2.1.0 document built from the normalized findings. */
import type { Finding, Severity } from '@shared/findings.js';

const LEVEL_BY_SEVERITY: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[]; 'security-severity'?: string };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number; startColumn?: number } } }[];
  partialFingerprints: { securevibeFingerprint: string };
  properties: { severity: Severity; priority: string; confidence: string; source: string; status: string; asvs: string[]; aisvs: string[]; sbd: string[] };
}

const SEVERITY_SCORE: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.5' };

export interface Sarif {
  $schema: string;
  version: '2.1.0';
  runs: {
    tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } };
    results: SarifResult[];
  }[];
}

export function buildSarif(findings: Finding[], toolVersion = '0.1.0'): Sarif {
  const ruleOrder: string[] = [];
  const rules = new Map<string, SarifRule>();
  for (const f of findings) {
    if (rules.has(f.ruleId)) continue;
    ruleOrder.push(f.ruleId);
    rules.set(f.ruleId, {
      id: f.ruleId,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description },
      properties: { tags: [f.source, ...f.cwe], 'security-severity': SEVERITY_SCORE[f.severity] },
    });
  }

  const results: SarifResult[] = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleOrder.indexOf(f.ruleId),
    level: LEVEL_BY_SEVERITY[f.severity],
    message: { text: `${f.description} ${f.impact}`.trim() },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.location?.file ?? f.location?.endpoint ?? 'unknown' },
          ...(f.location?.line ? { region: { startLine: f.location.line, ...(f.location.column ? { startColumn: f.location.column } : {}) } } : {}),
        },
      },
    ],
    partialFingerprints: { securevibeFingerprint: f.fingerprint },
    properties: {
      severity: f.severity,
      priority: f.priority,
      confidence: f.confidence,
      source: f.source,
      status: f.status,
      asvs: f.mappings.asvs,
      aisvs: f.mappings.aisvs,
      sbd: f.mappings.sbd,
    },
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'SecureVibe', version: toolVersion, informationUri: 'https://github.com/owasp/secure-by-design', rules: ruleOrder.map((id) => rules.get(id)!) } },
        results,
      },
    ],
  };
}
