import { describe, expect, it } from 'vitest';
import { DesignArtifactsSchema, type DesignArtifacts } from '@shared/design.js';
import { DesignProfileSchema } from '@shared/profile.js';
import type { Attestation } from '@shared/project.js';
import { deriveDesign, profileHash } from '../../src/design/index.js';
import { frameworksForTests, makeKnowledge } from '../fixtures/design/knowledge.js';
import { allProfiles, clinicBookings, habitTracker, marketplace, teamInventory } from '../fixtures/design/profiles.js';

const knowledge = makeKnowledge();
const frameworks = frameworksForTests();
const NOW = new Date('2026-09-16T10:00:00.000Z');

function derive(profile: Parameters<typeof deriveDesign>[0], extra: Partial<Parameters<typeof deriveDesign>[1]> = {}): DesignArtifacts {
  return deriveDesign(profile, { knowledge, frameworks, now: NOW, ...extra });
}

/** Strips the timestamps and dates that legitimately differ between two derivations. */
function stable(design: DesignArtifacts): unknown {
  return JSON.parse(
    JSON.stringify({
      ...design,
      generatedAt: undefined,
      threatModel: design.threatModel ? { ...design.threatModel, performedAt: undefined } : undefined,
      adrs: design.adrs.map((a) => ({ ...a, date: undefined })),
    }),
  );
}

describe('deriveDesign: every fixture profile', () => {
  for (const { name, profile } of allProfiles) {
    const design = derive(profile);

    it(`${name}: produces artifacts that validate against DesignArtifactsSchema`, () => {
      expect(() => DesignArtifactsSchema.parse(design)).not.toThrow();
      expect(design.generatedAt).toBe(NOW.toISOString());
      expect(design.profileHash).toBe(profileHash(profile));
      expect(design.profileHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it(`${name}: is deterministic (same profile → same output, excluding generatedAt)`, () => {
      const again = derive(profile);
      expect(again).toEqual(design);
      const later = deriveDesign(profile, { knowledge, frameworks, now: new Date('2027-01-01T00:00:00.000Z') });
      expect(stable(later)).toEqual(stable(design));
    });

    it(`${name}: security requirements are numbered SR-01.. with mappings and driving fields`, () => {
      design.securityRequirements.forEach((r, i) => {
        expect(r.id).toBe(`SR-${String(i + 1).padStart(2, '0')}`);
        expect(r.drivenBy.length).toBeGreaterThan(0);
        expect(r.asvs.length + r.aisvs.length + r.sbd.length).toBeGreaterThan(0);
        expect(r.statement).not.toMatch(/\b(RBAC|IDOR|CSRF|TOTP)\b/);
      });
    });

    it(`${name}: architecture is internally consistent`, () => {
      const arch = design.architecture;
      const componentIds = new Set(arch.components.map((c) => c.id));
      const zoneIds = new Set(arch.trustZones.map((z) => z.id));
      for (const c of arch.components) expect(zoneIds.has(c.trustZone), c.id).toBe(true);
      for (const fl of arch.dataFlows) {
        expect(componentIds.has(fl.from), fl.id).toBe(true);
        expect(componentIds.has(fl.to), fl.id).toBe(true);
        expect(fl.controls.length, fl.id).toBeGreaterThan(0);
      }
      expect(arch.trustZones.map((z) => z.id)).toEqual(expect.arrayContaining(['browser', 'app', 'data']));
      expect(arch.mermaid).toMatch(/^flowchart LR/);
      expect(arch.mermaid).toContain('subgraph zone_browser');
      expect(arch.mermaid).toContain('subgraph zone_app');
      expect(arch.mermaid).toContain('subgraph zone_data');
      for (const fl of arch.dataFlows) expect(arch.mermaid).toContain(`${fl.id} ${fl.protocol}`);
      expect(arch.assumptions.length).toBeGreaterThan(2);
      expect(arch.plainLanguage).toContain(profile.deployment.owner.contactEmail);
    });

    it(`${name}: fills all 36 checklist controls with justification, score and actions for every "No"`, () => {
      expect(design.checklist).toHaveLength(36);
      expect(design.checklist.map((e) => e.id)).toEqual(frameworks.sbd.controls.map((c) => c.id));
      for (const e of design.checklist) {
        expect(e.justification.length, e.id).toBeGreaterThan(10);
        if (e.status === 'no') {
          expect(e.actions.length, e.id).toBeGreaterThan(0);
          expect(e.score, e.id).toBe({ low: 1, medium: 2, high: 4 }[e.severityIfNo]);
          if (e.critical) expect(e.mitigationPlan, e.id).toBeDefined();
        } else {
          expect(e.score, e.id).toBe(0);
        }
      }
    });

    it(`${name}: risk triage follows the framework rule exactly`, () => {
      const t = design.riskTriage;
      const expected = t.criticalNo.length > 0 || t.score >= 6 || t.triggers.some((x) => x.triggered);
      expect(t.escalate).toBe(expected);
      expect(t.threshold).toBe(6);
      expect(t.score).toBe(design.checklist.reduce((s, e) => s + e.score, 0));
      expect(t.triggers.map((x) => x.id)).toEqual(['sensitive-data', 'external-exposure', 'novel-technology', 'tier-1-impact']);
      expect(t.extraCareLabel).toBe(expected ? 'Extra care' : 'Standard care');
      expect(t.plainLanguage).not.toMatch(/escalat|score/i);
      expect(t.plainLanguage).toContain('What we did');
      expect(t.escalationHandling).toContain('no independent AppSec review was performed');
    });

    it(`${name}: threat model targets existing components/flows and is sorted by risk`, () => {
      const tm = design.threatModel!;
      const ids = new Set([...design.architecture.components.map((c) => c.id), ...design.architecture.dataFlows.map((f) => f.id)]);
      const order = { high: 3, medium: 2, low: 1 };
      expect(tm.performedBy).toBe('rules');
      expect(tm.threats.length).toBeGreaterThan(5);
      tm.threats.forEach((t, i) => {
        expect(ids.has(t.target), t.id).toBe(true);
        expect(t.mitigations.length, t.id).toBeGreaterThan(0);
        if (t.status !== 'mitigated') expect(t.actionItems.length, t.id).toBeGreaterThan(0);
        if (i > 0) expect(order[t.riskLevel]).toBeLessThanOrEqual(order[tm.threats[i - 1]!.riskLevel]);
      });
      for (const fl of design.architecture.dataFlows.filter((f) => f.crossesTrustBoundary)) {
        expect(tm.threats.some((t) => t.target === fl.id), fl.id).toBe(true);
      }
      expect(tm.trustBoundaries.length).toBeGreaterThan(1);
      expect(tm.entryPoints.length).toBeGreaterThan(1);
    });

    it(`${name}: has the fixed ADR list and the 25 security-contract rules`, () => {
      expect(design.adrs.map((a) => a.id)).toEqual(['ADR-001', 'ADR-002', 'ADR-003', 'ADR-004', 'ADR-005', 'ADR-006', 'ADR-007', 'ADR-008']);
      for (const adr of design.adrs) {
        expect(adr.date).toBe('2026-09-16');
        expect(adr.alternatives.length).toBeGreaterThan(0);
      }
      expect(design.securityContract.rules.map((r) => r.id)).toEqual(Array.from({ length: 25 }, (_, i) => `SC-${String(i + 1).padStart(2, '0')}`));
      expect(design.securityContract.version).toBe('1.0');
    });

    it(`${name}: writes a short plain-language summary with consequences and wizard copy`, () => {
      const sentences = design.plainLanguageSummary.split(/(?<=\.)\s+/).filter(Boolean);
      expect(sentences.length).toBeGreaterThanOrEqual(3);
      expect(sentences.length).toBeLessThanOrEqual(6);
      expect(design.plainLanguageSummary).toContain(profile.app.name);
      expect(design.consequences.length).toBeGreaterThan(1);
      expect(Object.keys(design.whatThisChanges)).toEqual(['about', 'users', 'data', 'features', 'deployment']);
      expect(design.whatThisChanges.about!.length).toBeGreaterThan(0);
      expect(design.whatThisChanges.deployment!.length).toBeGreaterThan(0);
    });
  }
});

describe('deriveDesign: habit tracker (single person, local only)', () => {
  const design = derive(habitTracker);

  it('has no accounts, level 1, standard care', () => {
    expect(design.buildSpec.features.auth).toBe(false);
    expect(design.buildSpec.features.adminMfa).toBe(false);
    expect(design.buildSpec.features.tlsMode).toBe('off');
    expect(design.applicability.targetLevel).toBe(1);
    expect(design.riskTriage.triggers.every((t) => !t.triggered)).toBe(true);
    expect(design.consequences).toContain('No sign-in: anyone who can use this computer can open the app');
    expect(design.consequences).not.toContain('People must sign in');
  });

  it('answers the auth-dependent controls N-A and the local-only ones per the rules', () => {
    const byId = new Map(design.checklist.map((e) => [e.id, e]));
    expect(byId.get('AC-02')?.status).toBe('n-a');
    expect(byId.get('AC-03')?.status).toBe('n-a');
    expect(byId.get('AC-01')?.status).toBe('n-a');
    expect(byId.get('AC-01')?.deploymentNote).toMatch(/TLS proxy/);
    expect(byId.get('DM-02')?.status).toBe('n-a');
    expect(byId.get('AC-05')?.status).toBe('no');
    expect(byId.get('MT-06')?.status).toBe('no');
    expect(byId.get('MT-06')?.mitigationPlan?.owner).toBe('owner:Sam Rivera');
    expect(design.riskTriage.criticalNo).toEqual(['MT-06']);
    expect(design.riskTriage.escalate).toBe(true);
  });

  it('selects only the always-on patterns', () => {
    expect(design.patterns.map((p) => p.id)).toEqual(['PAT-TRUST-ZONES']);
    expect(design.patterns[0]?.why).toBe('Habit Log uses PAT-TRUST-ZONES.');
  });

  it('has no vendor zone and no boundary-crossing flow except the browser', () => {
    expect(design.architecture.trustZones.map((z) => z.id)).toEqual(['browser', 'app', 'data']);
    expect(design.architecture.dataFlows.filter((f) => f.crossesTrustBoundary).map((f) => f.id)).toEqual(['F-01']);
  });

  it('ADR-001 records the no-accounts decision', () => {
    expect(design.adrs[0]?.title).toMatch(/no accounts/);
  });
});

describe('deriveDesign: team inventory (local network, invitations, uploads, contact data)', () => {
  const design = derive(teamInventory);

  it('turns on sign-in, admin MFA, uploads, email (invitations) and self-signed TLS', () => {
    const f = design.buildSpec.features;
    expect(f.auth).toBe(true);
    expect(f.adminMfa).toBe(true);
    expect(f.uploads).toBe(true);
    expect(f.email).toBe(true);
    expect(f.tlsMode).toBe('selfsigned');
    expect(f.lanBinding).toBe(true);
    expect(f.fieldEncryption).toBe(false);
    expect(design.applicability.targetLevel).toBe(2);
    expect(f.userMfa).toBe(true);
  });

  it('records the "Not sure" answer as an assumption', () => {
    expect(design.assumptionsMade).toEqual([
      'You were not sure about whether administrators use an authenticator app, so we chose the safer option: yes, they do.',
    ]);
  });

  it('marks AC-02 not applicable, with the answer as the reason, when the owner has no central sign-in system', () => {
    // An owner with no organization was rated at risk on AC-02 for ever. The wizard now asks, and "no" answers it.
    const withoutIdp = DesignProfileSchema.parse({ ...teamInventory, users: { ...teamInventory.users, centralSignIn: 'no' } });
    const design = deriveDesign(withoutIdp, { knowledge, frameworks, now: NOW });
    const entry = design.checklist.find((e) => e.id === 'AC-02')!;
    expect(entry.status).toBe('n-a');
    expect(entry.justification).toContain('no central sign-in system');
    expect(entry.actions).toEqual([]);
    expect(design.riskTriage.criticalNo).not.toContain('AC-02');
    // "not sure" is read as "yes": the connection stays a later action, and the control stays "no".
    const unsure = deriveDesign(DesignProfileSchema.parse({ ...teamInventory, users: { ...teamInventory.users, centralSignIn: 'not-sure' } }), { knowledge, frameworks, now: NOW });
    expect(unsure.checklist.find((e) => e.id === 'AC-02')!.status).toBe('no');
  });

  it('answers AC-01 and DM-02 yes on the local network and AC-02 no with a plan', () => {
    const byId = new Map(design.checklist.map((e) => [e.id, e]));
    expect(byId.get('AC-01')?.status).toBe('yes');
    expect(byId.get('DM-02')?.status).toBe('yes');
    expect(byId.get('AC-02')?.status).toBe('no');
    expect(byId.get('AC-02')?.mitigationPlan).toEqual({
      owner: 'owner:Priya Nair',
      dueBy: 'before multi-team use',
      action: 'Adopt a central identity provider (OIDC) if the organization has one.',
    });
    expect(byId.get('AC-06')?.status).toBe('yes');
    expect(byId.get('RR-02')?.status).toBe('yes');
  });

  it('keeps the profile roles with the manager as administrator', () => {
    expect(design.adrs[0]?.decision).toContain('Manager (administrator)');
    expect(design.adrs[0]?.decision).toContain('Shop staff');
  });

  it('includes the uploads and email flows with their controls', () => {
    const flows = new Map(design.architecture.dataFlows.map((f) => [f.id, f]));
    expect(flows.get('F-03')?.controls).toContain('TPL-UPLOAD-02');
    expect(flows.get('F-05')?.crossesTrustBoundary).toBe(true);
    expect(design.patterns.map((p) => p.id)).toContain('PAT-EGRESS-ALLOWLIST');
    expect(design.patterns.find((p) => p.id === 'PAT-EGRESS-ALLOWLIST')?.appliesTo).toEqual(['email-service', 'F-05']);
  });
});

describe('deriveDesign: clinic bookings (customers, health data, AI, internet later, high impact)', () => {
  const design = derive(clinicBookings);

  it('encrypts fields, forces admin MFA, moderates the assistant and defers TLS to the proxy', () => {
    const f = design.buildSpec.features;
    expect(f.fieldEncryption).toBe(true);
    expect(f.adminMfa).toBe(true);
    expect(f.ai).toBe(true);
    expect(f.aiActions).toBe(false);
    expect(f.aiModeration).toBe(true);
    expect(f.retentionJobs).toBe(true);
    expect(f.scheduler).toBe(true);
    expect(f.tlsMode).toBe('proxy');
    expect(design.buildSpec.sessionPolicy).toEqual({ idleMinutes: 15, absoluteHours: 8, maxConcurrent: 5 });
  });

  it('raises severity for high business impact and answers DM-02 / AC-01 "no" until deployed', () => {
    const byId = new Map(design.checklist.map((e) => [e.id, e]));
    expect(byId.get('MT-02')?.severityIfNo).toBe('medium');
    expect(byId.get('MT-02')?.score).toBe(2);
    expect(byId.get('AC-05')?.severityIfNo).toBe('high');
    expect(byId.get('DM-02')?.status).toBe('no');
    expect(byId.get('DM-02')?.mitigationPlan?.dueBy).toBe('before internet deployment');
    expect(byId.get('AC-01')?.status).toBe('no');
    expect(design.riskTriage.criticalNo).toEqual(expect.arrayContaining(['DM-02', 'AC-01', 'AC-02', 'MT-06']));
  });

  it('triggers all four escalation triggers and explains them without jargon', () => {
    expect(design.riskTriage.triggers.map((t) => t.triggered)).toEqual([true, true, true, true]);
    expect(design.riskTriage.level).toBe('high');
    expect(design.riskTriage.plainLanguage).toContain('Clinic Bookings gets extra care');
    expect(design.riskTriage.plainLanguage).toContain('health information');
    expect(design.riskTriage.escalationHandling).toContain('pending');
  });

  it('records the acknowledgment date when given', () => {
    const acked = derive(clinicBookings, { escalationAcknowledgedAt: '2026-09-17T09:00:00.000Z' });
    expect(acked.riskTriage.escalationHandling).toContain('on 2026-09-17');
    expect(acked.riskTriage.plainLanguage).toContain('You acknowledged this review on 2026-09-17');
  });

  it('adds AI, email and vendor-zone elements and an open TLS threat with an action', () => {
    expect(design.architecture.trustZones.map((z) => z.id)).toContain('vendor');
    expect(design.architecture.components.map((c) => c.id)).toEqual(expect.arrayContaining(['ai-provider', 'email-service', 'scheduler']));
    const tm = design.threatModel!;
    const transit = tm.threats.find((t) => t.target === 'F-01' && t.stride === 'information-disclosure')!;
    expect(transit.status).toBe('open');
    expect(transit.actionItems[0]).toMatch(/HTTPS reverse proxy/);
    expect(tm.threats.some((t) => t.target === 'F-04' && t.description.includes('prompt injection'))).toBe(true);
    expect(design.securityRequirements.some((r) => r.aisvs.includes('C2.1.3'))).toBe(true);
  });

  it('evaluates AISVS and keeps AISVS Appendix C', () => {
    expect(design.applicability.aisvs.enabled).toBe(true);
    expect(design.applicability.aisvs.applicable).toContain('C2.1.3');
    expect(design.applicability.aisvs.notApplicable.some((n) => n.id === 'C1.1.1')).toBe(true);
    expect(design.applicability.appendixC.applicable).toContain('AC.4.1');
    expect(design.applicability.asvs.notApplicable.some((n) => n.id === 'V10.4.1')).toBe(true);
    expect(design.applicability.asvs.applicable).toContain('V6.2.1');
  });

  it('lists the consequences the owner must know about', () => {
    expect(design.consequences).toEqual(
      expect.arrayContaining([
        'People must sign in',
        'Administrators need an authenticator app on their phone',
        'Every person can turn on an authenticator app for their own account',
        'Records about people are deleted automatically after 24 months and cannot be recovered afterwards',
        'The AI assistant needs an Anthropic API key and costs money per use (each person has a daily budget)',
        'Before going online you must set up an HTTPS proxy and follow the "going online" checklist',
      ]),
    );
    expect(design.plainLanguageSummary).toContain('extra care');
  });
});

describe('deriveDesign: marketplace (public, payments, API keys, external API, AI actions)', () => {
  const design = derive(marketplace);

  it('turns every feature on', () => {
    expect(design.buildSpec.features).toEqual({
      auth: true,
      adminMfa: true,
      userMfa: true,
      uploads: true,
      ai: true,
      aiActions: true, aiWebSearch: false,
      aiModeration: true,
      email: true,
      scheduler: true,
      publicApi: true,
      payments: true,
      fieldEncryption: true,
      retentionJobs: false,
      lanBinding: false,
      tlsMode: 'proxy',
    });
  });

  it('models every outside connection with a flow, a dependency and threats', () => {
    const flowIds = design.architecture.dataFlows.map((f) => f.id);
    expect(flowIds).toEqual(expect.arrayContaining(['F-01', 'F-02', 'F-03', 'F-04', 'F-05', 'F-06', 'F-07', 'F-08', 'F-21']));
    expect(design.architecture.externalDependencies.map((d) => d.name)).toEqual(
      expect.arrayContaining(['Anthropic API', 'Email server (SMTP)', 'Payment provider (to be chosen)', 'Shipping rates API', 'npm registry']),
    );
    const tm = design.threatModel!;
    expect(tm.threats.some((t) => t.target === 'F-21' && t.status === 'open')).toBe(true);
    expect(tm.threats.some((t) => t.target === 'F-04' && t.stride === 'elevation-of-privilege')).toBe(true);
    expect(tm.threats.some((t) => t.target === 'F-06')).toBe(true);
  });

  it('selects the feature patterns, including egress for AI, email and the external API', () => {
    const ids = design.patterns.map((p) => p.id);
    expect(ids).toEqual(
      expect.arrayContaining(['PAT-AI-HUMAN-APPROVAL', 'PAT-API-KEYS', 'PAT-PROVIDER-HOSTED-PAYMENTS', 'PAT-SCHEDULED-JOBS-LOCKED', 'PAT-TLS-PROXY', 'PAT-EGRESS-ALLOWLIST', 'PAT-FIELD-ENCRYPTION']),
    );
    expect(design.patterns.find((p) => p.id === 'PAT-EGRESS-ALLOWLIST')?.appliesTo).toEqual(['external-api-1', 'F-21', 'ai-provider', 'F-04', 'email-service', 'F-05']);
  });

  it('turns quick-mode inferences and "Not sure" answers into assumptions', () => {
    expect(design.assumptionsMade).toEqual([
      'You were not sure about how bad a day of downtime would be, so we chose the safer option: a serious hit to the business.',
      'From your description we assumed which roles exist: Administrator, Maker and Buyer. Please check this.',
      'From your description we assumed whether it runs scheduled jobs: yes. Please check this.',
      'From your description we assumed which records it keeps: Listings and Order. Please check this.',
    ]);
  });

  it('applies AISVS action controls', () => {
    expect(design.applicability.aisvs.applicable).toContain('C9.2.1');
    expect(design.securityRequirements.some((r) => r.aisvs.includes('C9.2.1'))).toBe(true);
    expect(design.consequences).toContain('The assistant can suggest changes, but a person must confirm each one');
  });
});

describe('deriveDesign: attestations and previous artifacts', () => {
  const attestation: Attestation = {
    id: 'att_1',
    requirementId: 'MT-06',
    standard: 'sbd',
    result: 'yes',
    note: 'Rehearsed on 2026-09-01',
    attestedBy: 'Sam Rivera',
    attestedAt: '2026-09-01T00:00:00.000Z',
  };

  it('an owner attestation turns MT-06 into "yes" with manual evidence', () => {
    const design = derive(habitTracker, { attestations: [attestation] });
    const mt06 = design.checklist.find((e) => e.id === 'MT-06')!;
    expect(mt06.status).toBe('yes');
    expect(mt06.evidence).toContain('manual:attestation:att_1');
    expect(design.riskTriage.criticalNo).toEqual([]);
    expect(design.riskTriage.escalate).toBe(false);
    expect(design.riskTriage.extraCareLabel).toBe('Standard care');
    expect(design.riskTriage.plainLanguage).toContain('standard care');
  });

  it('a "no" attestation does not count', () => {
    const design = derive(habitTracker, { attestations: [{ ...attestation, result: 'no' }] });
    expect(design.checklist.find((e) => e.id === 'MT-06')?.status).toBe('no');
  });

  it('carries over the peer review and a Claude threat model for the same profile, keeps ADR dates', () => {
    const first = derive(clinicBookings);
    const previous: DesignArtifacts = {
      ...first,
      peerReview: { performedBy: 'claude', model: 'claude-opus-5', performedAt: '2026-09-10T00:00:00.000Z', summary: 'Looks fine.', suggestions: [] },
      threatModel: { ...first.threatModel!, performedBy: 'claude', model: 'claude-opus-5', summary: 'LLM model' },
      adrs: first.adrs.map((a) => ({ ...a, date: '2026-01-01' })),
      contractHash: 'abc',
    };
    const again = derive(clinicBookings, { previous, now: new Date('2026-12-01T00:00:00.000Z') });
    expect(again.peerReview?.summary).toBe('Looks fine.');
    expect(again.threatModel?.performedBy).toBe('claude');
    expect(again.threatModel?.summary).toBe('LLM model');
    expect(again.adrs.every((a) => a.date === '2026-01-01')).toBe(true);
    expect(again.contractHash).toBe('abc');
  });

  it('drops a Claude threat model and the contract hash when the profile changed, but keeps the peer review', () => {
    const first = derive(clinicBookings);
    const previous: DesignArtifacts = {
      ...first,
      peerReview: { performedBy: 'claude', performedAt: '2026-09-10T00:00:00.000Z', summary: 'Older review.', suggestions: [] },
      threatModel: { ...first.threatModel!, performedBy: 'claude', summary: 'LLM model' },
      contractHash: 'abc',
    };
    const changed = { ...clinicBookings, app: { ...clinicBookings.app, name: 'Clinic Bookings 2' } };
    const again = derive(changed, { previous });
    expect(again.peerReview?.summary).toBe('Older review.');
    expect(again.threatModel?.performedBy).toBe('rules');
    expect(again.contractHash).toBeUndefined();
    const adr1 = again.adrs.find((a) => a.id === 'ADR-001')!;
    expect(adr1.date).toBe('2026-09-16');
  });

  it('profileHash ignores meta bookkeeping but not decisions', () => {
    const confirmed = { ...habitTracker, meta: { ...habitTracker.meta, confirmed: false } };
    expect(profileHash(confirmed)).toBe(profileHash(habitTracker));
    const lan = { ...habitTracker, deployment: { ...habitTracker.deployment, target: 'local-network' as const } };
    expect(profileHash(lan)).not.toBe(profileHash(habitTracker));
  });

  it('a self-assessment evaluates AISVS even without an AI feature', () => {
    const design = derive(habitTracker, { selfAssessment: true });
    expect(design.applicability.aisvs.enabled).toBe(true);
    expect(design.applicability.aisvs.applicable).toContain('C9.2.1');
  });
});
