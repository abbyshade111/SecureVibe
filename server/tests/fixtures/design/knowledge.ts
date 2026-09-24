/**
 * Minimal knowledge base for the design-engine tests: a compact sbd-rules table (all 36 controls, mirroring
 * CONTRACTS §7 in spirit), a handful of patterns and an almost empty applicability config. The real files under
 * data/knowledge are written by another module; these fixtures keep the tests independent of them.
 */
import type { ApplicabilityConfig, PatternCatalogEntry, SbdRule } from '@shared/knowledge.js';
import { loadFrameworks, type Frameworks, type Knowledge } from '../../../src/frameworks/index.js';

type When = SbdRule['outcomes'][number]['when'];
type Status = 'yes' | 'no' | 'n-a';
type Row = [When, Status, Partial<SbdRule['outcomes'][number]>?];

const NO_ACTION = { text: 'Review this control with a developer.', owner: 'developer', dueBy: 'before the app is used for real work' };

function rule(id: string, severityIfNo: SbdRule['severityIfNo'], rows: Row[]): SbdRule {
  return {
    id,
    severityIfNo,
    outcomes: rows.map(([when, status, extra]) => ({
      when,
      status,
      justification: extra?.justification ?? `Fixture justification for ${id} (${when} → ${status}).`,
      evidence: extra?.evidence ?? (status === 'yes' ? [`design:${id}`] : []),
      actions: extra?.actions ?? (status === 'no' ? [NO_ACTION] : []),
      ...(extra?.deploymentNote ? { deploymentNote: extra.deploymentNote } : {}),
      ...(extra?.deploymentTimeStatus ? { deploymentTimeStatus: extra.deploymentTimeStatus } : {}),
      ...(extra?.note ? { note: extra.note } : {}),
    })),
  };
}

export const sbdRulesFixture: SbdRule[] = [
  rule('AS-01', 'high', [['always', 'yes', { evidence: ['template:TPL-TRUSTZONES-01', 'design:architecture'], deploymentTimeStatus: 'yes', note: 'Your app is built in separate compartments.' }]]),
  rule('AS-02', 'low', [['always', 'n-a']]),
  rule('AS-03', 'medium', [['always', 'yes']]),
  rule('AS-04', 'low', [['always', 'n-a']]),
  rule('AS-05', 'medium', [['always', 'yes', { evidence: ['template:TPL-CONTRACT-01'] }]]),
  rule('AS-06', 'low', [['always', 'n-a']]),
  rule('AS-07', 'low', [['always', 'yes']]),
  rule('AS-08', 'low', [['always', 'n-a']]),
  rule('DM-01', 'medium', [['personal-data', 'yes', { evidence: ['doc:docs/data-protection.md'] }], ['always', 'yes']]),
  rule('DM-02', 'high', [
    ['internet-later', 'no', { actions: [{ text: 'Put the app behind a TLS (HTTPS) reverse proxy before anyone reaches it over the internet.', owner: 'hosting-provider', dueBy: 'before internet deployment' }], deploymentTimeStatus: 'no' }],
    ['local-network', 'yes', { evidence: ['template:TPL-TLS-01', 'template:TPL-CRYPTO-01'], deploymentTimeStatus: 'deferred' }],
    ['sensitive-data', 'yes', { evidence: ['template:TPL-CRYPTO-01'], deploymentTimeStatus: 'deferred' }],
    ['personal-data', 'yes', { evidence: ['template:TPL-CRYPTO-01'], deploymentTimeStatus: 'deferred' }],
    ['always', 'n-a', { deploymentTimeStatus: 'no', deploymentNote: 'If the app is ever reached over a network it must run behind a TLS proxy.' }],
  ]),
  rule('DM-03', 'medium', [['always', 'yes', { evidence: ['template:TPL-IDEMPOTENCY-01'] }]]),
  rule('DM-04', 'low', [['always', 'n-a']]),
  rule('DM-05', 'medium', [['personal-data', 'yes', { evidence: ['doc:docs/data-retention.md'] }], ['always', 'yes']]),
  rule('DM-06', 'low', [['always', 'n-a']]),
  rule('RR-01', 'medium', [['always', 'yes', { evidence: ['template:TPL-ERRORS-01'] }]]),
  rule('RR-02', 'medium', [['external-apis', 'yes'], ['ai', 'yes'], ['email', 'yes'], ['always', 'n-a']]),
  rule('RR-03', 'low', [['scheduler', 'yes', { evidence: ['template:TPL-SCHED-01'] }], ['always', 'n-a']]),
  rule('RR-04', 'low', [['always', 'n-a']]),
  rule('RR-05', 'medium', [['always', 'yes']]),
  rule('RR-06', 'high', [['always', 'yes', { evidence: ['template:TPL-RESILIENCE-01'] }]]),
  rule('RR-07', 'medium', [['always', 'yes', { evidence: ['template:TPL-RATE-01'] }]]),
  rule('RR-08', 'low', [['always', 'n-a']]),
  rule('AC-01', 'high', [
    ['local-only', 'n-a', { deploymentTimeStatus: 'no', deploymentNote: 'Once on a network the app must run behind a TLS proxy.' }],
    ['local-network', 'yes', { evidence: ['template:TPL-TLS-01'] }],
    ['internet-later', 'no', { actions: [{ text: 'TLS proxy before exposure (docs/deployment.md).', owner: 'hosting-provider', dueBy: 'before internet deployment' }] }],
  ]),
  rule('AC-02', 'high', [
    ['no-central-sign-in', 'n-a', { justification: 'You said your organization has no central sign-in system, so there is nothing to connect the app to.' }],
    ['auth', 'no', { justification: 'Local accounts with admin MFA; no central identity provider.', actions: [{ text: 'Adopt a central identity provider (OIDC) if the organization has one.', owner: 'developer', dueBy: 'before multi-team use' }] }],
    ['no-auth', 'n-a'],
  ]),
  rule('AC-03', 'medium', [['auth', 'yes', { evidence: ['template:TPL-AUTHZ-01'] }], ['no-auth', 'n-a']]),
  rule('AC-04', 'low', [['always', 'n-a']]),
  rule('AC-05', 'medium', [['always', 'no', { justification: 'Secrets live in .env with strict permissions; no secret manager.', actions: [{ text: 'Move secrets to a secret manager when deploying.', owner: 'hosting-provider', dueBy: 'before internet deployment' }] }]]),
  rule('AC-06', 'medium', [['personal-data', 'yes', { evidence: ['doc:docs/data-protection.md'] }], ['always', 'n-a']]),
  rule('AC-07', 'low', [['always', 'n-a']]),
  rule('MT-01', 'medium', [['always', 'yes', { evidence: ['template:TPL-LOG-01', 'template:TPL-LOG-03'] }]]),
  rule('MT-02', 'low', [['always', 'no', { actions: [{ text: 'Add monitoring when deployed.', owner: 'owner', dueBy: 'before internet deployment' }] }]]),
  rule('MT-03', 'medium', [['always', 'yes', { evidence: ['template:TPL-TESTS-01'] }]]),
  rule('MT-04', 'medium', [['always', 'yes']]),
  rule('MT-05', 'low', [['always', 'yes']]),
  rule('MT-06', 'high', [
    ['attested', 'yes', { evidence: ['doc:docs/incident-response.md'] }],
    ['always', 'no', { justification: 'A plan exists but has not been rehearsed.', actions: [{ text: 'Read and rehearse the incident plan.', owner: 'owner', dueBy: 'before the app is used for real work' }] }],
  ]),
  rule('MT-07', 'high', [['always', 'yes', { evidence: ['template:TPL-LOG-05'], deploymentTimeStatus: 'no' }]]),
];

function pattern(id: string, when: PatternCatalogEntry['when'], extra: Partial<PatternCatalogEntry> = {}): PatternCatalogEntry {
  return {
    id,
    name: extra.name ?? id.replace('PAT-', '').toLowerCase().replace(/-/g, ' '),
    principle: extra.principle ?? 'secure-defaults',
    sbdDomain: extra.sbdDomain ?? 'A',
    description: `${id} description`,
    whyTemplate: extra.whyTemplate ?? `{appName} uses ${id}.`,
    implementedBy: extra.implementedBy ?? [],
    sbdChecklist: extra.sbdChecklist ?? [],
    asvs: extra.asvs ?? [],
    aisvs: extra.aisvs ?? [],
    when,
  };
}

export const patternsFixture: PatternCatalogEntry[] = [
  pattern('PAT-TRUST-ZONES', 'always', { principle: 'zero-trust-explicit-boundaries', implementedBy: ['TPL-TRUSTZONES-01'], sbdChecklist: ['AS-01'] }),
  pattern('PAT-DENY-BY-DEFAULT-ROUTES', 'auth', { principle: 'least-privilege', sbdDomain: 'D', implementedBy: ['TPL-AUTHZ-01'], sbdChecklist: ['AC-03'] }),
  pattern('PAT-FIELD-ENCRYPTION', 'sensitive-data', { principle: 'defense-in-depth', sbdDomain: 'B', implementedBy: ['TPL-CRYPTO-01'], sbdChecklist: ['DM-02'] }),
  pattern('PAT-RETENTION', 'personal-data', { sbdDomain: 'B', sbdChecklist: ['DM-05'] }),
  pattern('PAT-EGRESS-ALLOWLIST', 'external-apis', { principle: 'zero-trust-explicit-boundaries', implementedBy: ['TPL-OUTBOUND-01'], sbdChecklist: ['AS-01'] }),
  pattern('PAT-UPLOAD-QUARANTINE', 'uploads', { sbdDomain: 'B', implementedBy: ['TPL-UPLOAD-02'] }),
  pattern('PAT-AI-GUARDRAILS', 'ai', { principle: 'fail-secure-graceful-degradation', implementedBy: ['TPL-AI-03'] }),
  pattern('PAT-AI-HUMAN-APPROVAL', 'ai-actions', { principle: 'least-privilege', implementedBy: ['TPL-AI-ACTIONS-01'] }),
  pattern('PAT-USER-MFA', 'level2', { sbdDomain: 'D' }),
  pattern('PAT-TLS-PROXY', 'internet', { sbdDomain: 'D', sbdChecklist: ['AC-01', 'DM-02'] }),
  pattern('PAT-PROVIDER-HOSTED-PAYMENTS', 'payments', { sbdDomain: 'D', sbdChecklist: ['AC-06'] }),
  pattern('PAT-SCHEDULED-JOBS-LOCKED', 'scheduler', { sbdDomain: 'C', sbdChecklist: ['RR-03'] }),
  pattern('PAT-API-KEYS', 'public-api', { sbdDomain: 'D' }),
];

export const applicabilityFixture: ApplicabilityConfig = {
  rules: [
    { scope: 'V10', condition: 'oauth', notApplicableReason: 'No OAuth/OIDC: the app uses local accounts.' },
    { scope: 'V6', condition: 'auth' },
    { scope: 'V7', condition: 'auth' },
    { scope: 'V5', condition: 'uploads' },
    { scope: 'C1', condition: 'training', notApplicableReason: 'No model training.' },
    { scope: 'C9.2', condition: 'ai-actions' },
  ],
  manualOnly: ['AC.4.1', 'V11.1.1'],
  defaultVerificationClass: 'ai-assistable',
};

export function makeKnowledge(overrides: Partial<Knowledge> = {}): Knowledge {
  return {
    applicability: applicabilityFixture,
    sbdRules: sbdRulesFixture,
    patterns: patternsFixture,
    remediation: {},
    requirementsPlain: {},
    glossary: [],
    wizardCopy: {},
    examples: [],
    injectionPatterns: { high: [], medium: [] },
    missingFiles: [],
    ...overrides,
  };
}

/** The framework JSON files under data/frameworks are fixed inputs (CONTRACTS §0), so the real loader is used. */
export function frameworksForTests(): Frameworks {
  return loadFrameworks();
}
