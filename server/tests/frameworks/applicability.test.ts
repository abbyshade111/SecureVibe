import { describe, expect, it } from 'vitest';
import type { Applicability } from '@shared/design.js';
import {
  computeApplicability,
  deploymentNoteFor,
  isManualOnly,
  loadFrameworks,
  loadKnowledge,
  patternApplies,
  verificationClassFor,
} from '../../src/frameworks/index.js';
import {
  customersHealthAi,
  customersHealthAiActions,
  localNoAuth,
  selfAssessment,
} from '../fixtures/frameworks/profiles.js';

const knowledge = loadKnowledge({ warn: () => {} });
const frameworks = loadFrameworks();

type Bucket = { applicable: string[]; notApplicable: { id: string; reason: string }[]; outOfLevel: string[] };

function bucketOf(b: Bucket, id: string): 'applicable' | 'not-applicable' | 'out-of-level' | 'missing' {
  if (b.applicable.includes(id)) return 'applicable';
  if (b.notApplicable.some((n) => n.id === id)) return 'not-applicable';
  if (b.outOfLevel.includes(id)) return 'out-of-level';
  return 'missing';
}

function reasonOf(b: Bucket, id: string): string | undefined {
  return b.notApplicable.find((n) => n.id === id)?.reason;
}

function expectPartition(b: Bucket, total: number): void {
  const all = [...b.applicable, ...b.notApplicable.map((n) => n.id), ...b.outOfLevel];
  expect(all).toHaveLength(total);
  expect(new Set(all).size).toBe(total);
}

describe('computeApplicability: local-only, no sign-in, no personal data (level 1)', () => {
  const result: Applicability = computeApplicability(localNoAuth.profile, localNoAuth.buildSpec, knowledge, frameworks);

  it('targets level 1 and partitions every requirement exactly once', () => {
    expect(result.targetLevel).toBe(1);
    expect(result.targetLevelRule).toMatch(/Level 1/);
    expectPartition(result.asvs, frameworks.listRequirements('asvs').length);
    expectPartition(result.appendixC, frameworks.listRequirements('aisvs-appendix-c').length);
  });

  it('puts level 2 and 3 requirements out of level', () => {
    expect(bucketOf(result.asvs, 'V1.1.1')).toBe('out-of-level');
    expect(bucketOf(result.asvs, 'V6.2.9')).toBe('out-of-level');
    expect(bucketOf(result.asvs, 'V2.2.1')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.1.4')).toBe('out-of-level');
  });

  it('marks OAuth, JWT and authentication requirements not applicable with plain reasons', () => {
    expect(bucketOf(result.asvs, 'V10.4.1')).toBe('not-applicable');
    expect(reasonOf(result.asvs, 'V10.4.1')).toMatch(/local accounts/);
    expect(bucketOf(result.asvs, 'V9.1.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V6.2.1')).toBe('not-applicable');
    expect(reasonOf(result.asvs, 'V6.2.1')).toMatch(/no sign-in/);
    expect(bucketOf(result.asvs, 'V7.2.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V3.5.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V5.2.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V1.3.1')).toBe('not-applicable');
  });

  it('marks TLS requirements not applicable when tlsMode is off, with a deployment note', () => {
    expect(bucketOf(result.asvs, 'V3.3.1')).toBe('not-applicable');
    expect(reasonOf(result.asvs, 'V3.3.1')).toMatch(/this computer only/);
    expect(deploymentNoteFor('V3.3.1', knowledge)).toMatch(/TLS mode/);
    expect(bucketOf(result.asvs, 'V3.4.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V12.1.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V12.2.1')).toBe('not-applicable');
  });

  it('keeps always-applicable requirements', () => {
    expect(bucketOf(result.asvs, 'V3.4.2')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V3.4.3')).toBe('out-of-level');
    expect(bucketOf(result.asvs, 'V8.2.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V1.2.4')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V13.4.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V16.5.1')).toBe('out-of-level');
  });

  it('does not evaluate AISVS without an AI assistant but still evaluates Appendix C', () => {
    expect(result.aisvs.enabled).toBe(false);
    expect(result.aisvs.reason).toMatch(/no AI assistant/);
    expect(result.aisvs.applicable).toEqual([]);
    expect(bucketOf(result.appendixC, 'AC.4.1')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.1.1')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.12.1')).toBe('not-applicable');
    expect(reasonOf(result.appendixC, 'AC.12.1')).toMatch(/CI\/CD/);
    expect(bucketOf(result.appendixC, 'AC.13.1')).toBe('not-applicable');
  });
});

describe('computeApplicability: customers + health data + uploads + AI (level 2)', () => {
  const result = computeApplicability(customersHealthAi.profile, customersHealthAi.buildSpec, knowledge, frameworks);

  it('targets level 2 for sensitive data and partitions everything', () => {
    expect(result.targetLevel).toBe(2);
    expect(result.targetLevelRule).toMatch(/sensitive or regulated/);
    expectPartition(result.asvs, frameworks.listRequirements('asvs').length);
    expectPartition(result.aisvs, frameworks.listRequirements('aisvs').length);
    expectPartition(result.appendixC, frameworks.listRequirements('aisvs-appendix-c').length);
  });

  it('V10 and V17 are not applicable; level 3 stays out of level', () => {
    for (const id of frameworks.requirementIdsInScope('V10')) {
      const r = frameworks.getRequirement(id)!;
      expect(bucketOf(result.asvs, id), id).toBe(r.level > 2 ? 'out-of-level' : 'not-applicable');
    }
    expect(bucketOf(result.asvs, 'V17.1.1')).toBe('not-applicable');
    expect(reasonOf(result.asvs, 'V17.1.1')).toMatch(/WebRTC/);
    expect(bucketOf(result.asvs, 'V17.1.2')).toBe('out-of-level');
    expect(bucketOf(result.asvs, 'V6.7.1')).toBe('out-of-level');
  });

  it('authentication, uploads, TLS and rich-text rules apply', () => {
    expect(bucketOf(result.asvs, 'V6.2.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V6.2.9')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V6.5.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V6.6.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V6.6.3')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V6.8.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V7.6.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V5.2.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V5.4.3')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V3.3.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V12.1.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V1.3.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V1.3.5')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V8.4.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V1.3.11')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V15.4.1')).toBe('out-of-level');
  });

  it('service-to-service rules follow outbound connections (AI counts, external APIs do not exist)', () => {
    expect(bucketOf(result.asvs, 'V12.3.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V12.3.2')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V13.2.1')).toBe('not-applicable');
    expect(bucketOf(result.asvs, 'V13.2.4')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V16.4.3')).toBe('applicable');
    expect(deploymentNoteFor('V16.4.3', knowledge)).toMatch(/separate log service/);
  });

  it('evaluates AISVS with chapter-level exclusions', () => {
    expect(result.aisvs.enabled).toBe(true);
    expect(result.aisvs.reason).toMatch(/AI assistant/);
    expect(bucketOf(result.aisvs, 'C2.1.3')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C1.1.1')).toBe('not-applicable');
    expect(reasonOf(result.aisvs, 'C1.1.1')).toMatch(/train/);
    expect(bucketOf(result.aisvs, 'C3.1.1')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C3.3.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C4.1.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C5.2.2')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C5.2.4')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C6.1.2')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C6.1.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C7.1.1')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C7.4.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C10.2.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C11.2.2')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C11.2.3')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C11.4.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C12.1.1')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C12.3.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C9.1.2')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C9.6.1')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C9.5.3')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C9.5.4')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C2.2.1')).toBe('not-applicable');
  });

  it('conversation history enables memory controls but not vector-store ones', () => {
    expect(bucketOf(result.aisvs, 'C8.3.2')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C8.1.3')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C8.1.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C8.2.1')).toBe('not-applicable');
  });

  it('C9.2.* applies only when the assistant can take actions', () => {
    for (const id of frameworks.requirementIdsInScope('C9.2')) {
      const r = frameworks.getRequirement(id)!;
      if (r.level <= 2) expect(bucketOf(result.aisvs, id), id).toBe('not-applicable');
    }
    expect(reasonOf(result.aisvs, 'C9.2.1')).toMatch(/only answer questions/);
    expect(bucketOf(result.aisvs, 'C9.3.2')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C12.4.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C12.4.3')).toBe('applicable');

    const withActions = computeApplicability(
      customersHealthAiActions.profile,
      customersHealthAiActions.buildSpec,
      knowledge,
      frameworks,
    );
    expect(bucketOf(withActions.aisvs, 'C9.2.1')).toBe('applicable');
    expect(bucketOf(withActions.aisvs, 'C9.2.2')).toBe('applicable');
    expect(bucketOf(withActions.aisvs, 'C9.3.2')).toBe('applicable');
    expect(bucketOf(withActions.aisvs, 'C9.5.1')).toBe('applicable');
    expect(bucketOf(withActions.aisvs, 'C5.2.5')).toBe('applicable');
    expect(bucketOf(withActions.aisvs, 'C12.4.1')).toBe('applicable');
  });

  it('Appendix C: human review is applicable, pipeline families are not', () => {
    expect(bucketOf(result.appendixC, 'AC.4.1')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.4.4')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.5.1')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.10.2')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.6.1')).toBe('not-applicable');
    expect(bucketOf(result.appendixC, 'AC.6.3')).toBe('applicable');
    expect(bucketOf(result.appendixC, 'AC.9.1')).toBe('not-applicable');
    expect(bucketOf(result.appendixC, 'AC.7.3')).toBe('not-applicable');
    expect(bucketOf(result.appendixC, 'AC.11.7')).toBe('not-applicable');
  });
});

describe('computeApplicability: self-assessment', () => {
  const result = computeApplicability(selfAssessment.profile, selfAssessment.buildSpec, knowledge, frameworks, {
    selfAssessment: true,
  });

  it('evaluates AISVS and treats the generation agent as taking actions', () => {
    expect(result.targetLevel).toBe(2);
    expect(result.aisvs.enabled).toBe(true);
    expect(result.aisvs.reason).toMatch(/SecureVibe itself/);
    expect(bucketOf(result.aisvs, 'C9.2.1')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C9.3.2')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C9.5.1')).toBe('applicable');
    expect(bucketOf(result.aisvs, 'C10.1.1')).toBe('not-applicable');
    expect(bucketOf(result.aisvs, 'C1.1.1')).toBe('not-applicable');
    expect(bucketOf(result.appendixC, 'AC.4.1')).toBe('applicable');
  });

  it('external APIs make backend-communication requirements applicable', () => {
    expect(bucketOf(result.asvs, 'V13.2.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V12.3.1')).toBe('applicable');
    expect(bucketOf(result.asvs, 'V6.2.1')).toBe('not-applicable');
  });

  it('self-assessment also enables AISVS when the build spec has no ai feature flag', () => {
    const noFlag = computeApplicability(
      selfAssessment.profile,
      { ...selfAssessment.buildSpec, features: { ...selfAssessment.buildSpec.features, ai: false, aiActions: false } },
      knowledge,
      frameworks,
      { selfAssessment: true },
    );
    expect(noFlag.aisvs.enabled).toBe(true);
    expect(bucketOf(noFlag.aisvs, 'C9.2.1')).toBe('applicable');
  });
});

describe('verification classes and manual-only', () => {
  it('returns manual-only for the manual list regardless of rules', () => {
    expect(isManualOnly('AC.4.1', knowledge)).toBe(true);
    expect(verificationClassFor('AC.4.1', knowledge)).toBe('manual-only');
    expect(verificationClassFor('V11.1.1', knowledge)).toBe('manual-only');
    expect(verificationClassFor('V16.4.3', knowledge)).toBe('manual-only');
  });

  it('returns the rule class or the default', () => {
    expect(verificationClassFor('V8.1.1', knowledge)).toBe('doc-generated');
    expect(verificationClassFor('V1.2.4', knowledge)).toBe('scanner-clean');
    expect(verificationClassFor('V6.2.1', knowledge)).toBe('automatable');
    expect(verificationClassFor('V4.2.1', knowledge)).toBe('deployment-time');
    expect(verificationClassFor('V2.3.5', knowledge)).toBe('ai-assistable');
    expect(verificationClassFor('C3.1.1', knowledge)).toBe('doc-generated');
    expect(isManualOnly('V6.2.1', knowledge)).toBe(false);
  });

  it('uses the module-level knowledge when none is passed', () => {
    expect(verificationClassFor('AC.4.1')).toBe('manual-only');
    expect(deploymentNoteFor('V3.4.1')).toBeDefined();
    expect(deploymentNoteFor('V6.2.1')).toBeUndefined();
  });
});

describe('patternApplies', () => {
  it('selects patterns from the profile, with egress covering AI and email too', () => {
    const { profile, buildSpec } = customersHealthAi;
    expect(patternApplies({ when: 'always' }, profile, buildSpec)).toBe(true);
    expect(patternApplies({ when: 'auth' }, profile, buildSpec)).toBe(true);
    expect(patternApplies({ when: 'sensitive-data' }, profile, buildSpec)).toBe(true);
    expect(patternApplies({ when: 'personal-data' }, profile, buildSpec)).toBe(true);
    expect(patternApplies({ when: 'external-apis' }, profile, buildSpec)).toBe(true);
    expect(patternApplies({ when: 'ai-actions' }, profile, buildSpec)).toBe(false);
    expect(patternApplies({ when: 'internet' }, profile, buildSpec)).toBe(true);
    expect(patternApplies({ when: 'lan' }, profile, buildSpec)).toBe(false);
    expect(patternApplies({ when: 'level2' }, profile, buildSpec)).toBe(true);

    const local = localNoAuth;
    expect(patternApplies({ when: 'external-apis' }, local.profile, local.buildSpec)).toBe(false);
    expect(patternApplies({ when: 'personal-data' }, local.profile, local.buildSpec)).toBe(false);
    expect(patternApplies({ when: 'level2' }, local.profile, local.buildSpec)).toBe(false);
  });
});
