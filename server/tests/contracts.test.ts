/**
 * Contracts test (CONTRACTS.md preamble): every ASVS / AISVS / Appendix C / SbD id referenced by the knowledge base,
 * the template manifest and the scanner/compliance sources exists in data/frameworks; every manual-only id exists;
 * knowledge files agree with the framework data and with each other. Locations other modules have not written yet
 * are skipped with a note, never silently.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TemplateManifestSchema } from '@shared/knowledge.js';
import {
  checkReferencedIds,
  extractReferencedIds,
  loadFrameworks,
  loadKnowledge,
  REPO_ROOT,
  validateReferencedIds,
  verificationClassFor,
} from '../src/frameworks/index.js';

const frameworks = loadFrameworks();
const knowledge = loadKnowledge({ warn: () => {} });

const MANIFEST_PATH = join(REPO_ROOT, 'templates/secure-web-app/securevibe.manifest.json');
const SCANNERS_DIR = join(REPO_ROOT, 'server/src/scanners');

function note(message: string): void {
  process.stdout.write(`[contracts] ${message}\n`);
}

function readSources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) readSources(full, out);
    else if (/\.(ts|json)$/.test(entry)) out.push(readFileSync(full, 'utf8'));
  }
  return out;
}

describe('framework ids referenced across the repository', () => {
  it('every referenced id exists in data/frameworks (missing locations are skipped with a note)', () => {
    const result = checkReferencedIds(REPO_ROOT, frameworks);
    for (const s of result.skipped) note(`skipped ${s}: not written yet`);
    expect(result.scannedFiles).toBeGreaterThan(0);
    expect(result.problems, JSON.stringify(result.problems, null, 2)).toEqual([]);
  });

  it('id extraction and validation behave as the test relies on', () => {
    expect(extractReferencedIds('see V6.2.1, C2.1.3, AC.4.1 and AS-01 (not TPL-AUTH-01, not V6.2)')).toEqual([
      'V6.2.1',
      'C2.1.3',
      'AC.4.1',
      'AS-01',
    ]);
    expect(validateReferencedIds(['V6.2.1', 'V6.2.99', 'AC-01', 'ZZ-01'], frameworks)).toEqual({
      known: ['V6.2.1', 'AC-01'],
      unknown: ['V6.2.99', 'ZZ-01'],
    });
  });
});

describe('applicability.json', () => {
  it('every rule scope is a known chapter, section or requirement', () => {
    const unknown = knowledge.applicability.rules.map((r) => r.scope).filter((s) => !frameworks.hasScope(s));
    expect(unknown).toEqual([]);
  });

  it('every manual-only id exists and is classified manual-only', () => {
    for (const id of knowledge.applicability.manualOnly) {
      expect(frameworks.getRequirement(id), id).toBeDefined();
      expect(verificationClassFor(id, knowledge), id).toBe('manual-only');
    }
    expect(knowledge.applicability.manualOnly).toContain('AC.4.1');
  });

  it('never-style conditions always carry a plain-language reason', () => {
    const missing = knowledge.applicability.rules
      .filter((r) =>
        ['never', 'oauth', 'authorization-server', 'webrtc', 'jwt', 'rag', 'mcp', 'multi-tenant', 'training'].includes(
          r.condition,
        ),
      )
      .filter((r) => !r.notApplicableReason)
      .map((r) => r.scope);
    expect(missing).toEqual([]);
  });

  it('requirement-level rules inside a conditional chapter repeat the chapter condition', () => {
    // A requirement rule replaces the chapter rule, so "V6.2.1 always" would leak into apps without sign-in.
    const chapterConditions = new Map(
      knowledge.applicability.rules
        .filter((r) => /^(V\d+|C\d+)$/.test(r.scope) && r.condition !== 'always')
        .map((r) => [r.scope, r.condition]),
    );
    const leaks = knowledge.applicability.rules
      .filter((r) => r.condition === 'always')
      .filter((r) => chapterConditions.has(r.scope.split('.')[0] ?? ''))
      .map((r) => r.scope);
    expect(leaks).toEqual([]);
  });
});

describe('sbd-rules.json', () => {
  it('covers exactly the 36 checklist controls with the framework severities', () => {
    const ruleIds = knowledge.sbdRules.map((r) => r.id).sort();
    const controlIds = frameworks.sbd.controls.map((c) => c.id).sort();
    expect(ruleIds).toEqual(controlIds);
    for (const rule of knowledge.sbdRules) {
      expect(rule.severityIfNo, rule.id).toBe(frameworks.getSbdControl(rule.id)?.severityIfNo);
      expect(rule.outcomes.length, rule.id).toBeGreaterThan(0);
      // Every profile must match some outcome: a catch-all, or one outcome per deployment target.
      const whens = rule.outcomes.map((o) => o.when);
      const exhaustive =
        whens.includes('always') ||
        (['local-only', 'local-network', 'internet-later'] as const).every((w) => whens.includes(w)) ||
        (whens.includes('auth') && whens.includes('no-auth'));
      expect(exhaustive, `${rule.id} must have an outcome for every profile`).toBe(true);
    }
  });

  it("every 'no' outcome has at least one action and every outcome a justification", () => {
    for (const rule of knowledge.sbdRules) {
      for (const o of rule.outcomes) {
        expect(o.justification.length, `${rule.id}/${o.when}`).toBeGreaterThan(20);
        if (o.status === 'no') expect(o.actions.length, `${rule.id}/${o.when} needs an action`).toBeGreaterThan(0);
      }
    }
  });

  it('evidence pointers reference known patterns and well-formed control ids', () => {
    const patternIds = new Set(knowledge.patterns.map((p) => p.id));
    for (const rule of knowledge.sbdRules) {
      for (const o of rule.outcomes) {
        for (const e of o.evidence) {
          expect(e, `${rule.id}: ${e}`).toMatch(/^(template:TPL-[A-Z-]+-\d\d|design:[A-Za-z-]+|doc:.+|attestation:.+)$/);
          if (e.startsWith('design:PAT-')) expect(patternIds.has(e.slice('design:'.length)), e).toBe(true);
        }
      }
    }
  });
});

describe('patterns.json', () => {
  const EXPECTED = [
    'PAT-TRUST-ZONES',
    'PAT-DENY-BY-DEFAULT-ROUTES',
    'PAT-LEAST-PRIVILEGE-ROLES',
    'PAT-SECURE-DEFAULT-HEADERS',
    'PAT-CONTRACT-FIRST-VALIDATION',
    'PAT-FAIL-SECURE-ERRORS',
    'PAT-OBSERVABILITY-EVENTS',
    'PAT-AUDIT-CHAIN',
    'PAT-IDEMPOTENT-MUTATIONS',
    'PAT-TIMEOUTS-HEALTH',
    'PAT-RATE-LIMITS',
    'PAT-SECRETS-FROM-ENV',
    'PAT-DATA-CLASSIFICATION',
    'PAT-FIELD-ENCRYPTION',
    'PAT-RETENTION',
    'PAT-ADMIN-MFA',
    'PAT-USER-MFA',
    'PAT-EGRESS-ALLOWLIST',
    'PAT-UPLOAD-QUARANTINE',
    'PAT-AI-GUARDRAILS',
    'PAT-AI-HUMAN-APPROVAL',
    'PAT-SBOM-PINNED-DEPS',
    'PAT-IR-PLAN',
    'PAT-TLS-PROXY',
    'PAT-API-KEYS',
    'PAT-PROVIDER-HOSTED-PAYMENTS',
    'PAT-SCHEDULED-JOBS-LOCKED',
  ];

  it('contains exactly the CONTRACTS §5 patterns', () => {
    expect(knowledge.patterns.map((p) => p.id).sort()).toEqual([...EXPECTED].sort());
  });

  it('references only known checklist and requirement ids and uses the {appName} placeholder', () => {
    for (const p of knowledge.patterns) {
      expect(p.whyTemplate, p.id).toContain('{appName}');
      const { unknown } = validateReferencedIds([...p.sbdChecklist, ...p.asvs, ...p.aisvs], frameworks);
      expect(unknown, p.id).toEqual([]);
    }
  });

  it('implementedBy controls exist in the template manifest (skipped until the template is written)', () => {
    if (!existsSync(MANIFEST_PATH)) {
      note('skipped manifest control check: templates/secure-web-app/securevibe.manifest.json not written yet');
      return;
    }
    const manifest = TemplateManifestSchema.parse(JSON.parse(readFileSync(MANIFEST_PATH, 'utf8')));
    const controlIds = new Set(manifest.controls.map((c) => c.id));
    const missing = knowledge.patterns.flatMap((p) => p.implementedBy.filter((id) => !controlIds.has(id)).map((id) => `${p.id} → ${id}`));
    expect(missing).toEqual([]);
    const sbdEvidence = knowledge.sbdRules
      .flatMap((r) => r.outcomes.flatMap((o) => o.evidence))
      .filter((e) => e.startsWith('template:'))
      .map((e) => e.slice('template:'.length))
      .filter((id) => !controlIds.has(id));
    expect(sbdEvidence).toEqual([]);
  });
});

describe('knowledge references into scanner code', () => {
  /** Where each rule family lives (CONTRACTS §2-§4); a family is skipped until its directory exists. */
  const RULE_FAMILY_DIRS: Record<string, string> = {
    sast: join(SCANNERS_DIR, 'sast', 'rules'),
    dast: join(SCANNERS_DIR, 'dast', 'probes'),
    config: join(SCANNERS_DIR, 'config'),
    secrets: join(SCANNERS_DIR, 'secrets'),
    deps: join(SCANNERS_DIR, 'deps'),
  };

  it('remediation rule ids appear in scanner sources (families are skipped until their code is written)', () => {
    const ruleIds = Object.keys(knowledge.remediation);
    if (ruleIds.length === 0) {
      note('skipped remediation rule-id check: data/knowledge/remediation.json not written yet');
      return;
    }
    const missing: string[] = [];
    for (const [family, dir] of Object.entries(RULE_FAMILY_DIRS)) {
      const familyIds = ruleIds.filter((id) => id.startsWith(`${family}.`));
      if (familyIds.length === 0) continue;
      if (!existsSync(dir)) {
        note(`skipped ${family}.* rule-id check (${familyIds.length} ids): ${relative(REPO_ROOT, dir)} not written yet`);
        continue;
      }
      const sources = readSources(dir).join('\n');
      missing.push(...familyIds.filter((id) => !sources.includes(id)));
    }
    expect(missing).toEqual([]);
  });
});
