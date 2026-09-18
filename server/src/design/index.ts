/**
 * The SbD engine: from a validated DesignProfile derive every design artifact deterministically (no LLM).
 *
 *   deriveDesign(profile, deps)      SbD steps 1-4, 6, 7, 8 (peer review is supplied by server/src/llm and carried over)
 *   buildSpecFor(profile)            feature toggles + generation brief
 *   whatThisChanges(partialProfile)  live wizard copy
 *   renderDesignMarkdown(design)     design/*.md files for design freeze
 *   profileHash(profile)             sha256 of the canonical decision-relevant profile
 */
import type { DesignArtifacts, ThreatModel } from '@shared/design.js';
import type { DesignProfile } from '@shared/profile.js';
import { computeApplicability } from '../frameworks/index.js';
import { deriveAdrs } from './adrs.js';
import { deriveArchitecture } from './architecture.js';
import { buildSpecFor } from './build-spec.js';
import { fillChecklist } from './checklist.js';
import { profileFacts } from './conditions.js';
import { securityContractFor } from './contract.js';
import { profileHash } from './hash.js';
import { selectPatterns } from './patterns.js';
import { deriveSecurityRequirements } from './requirements.js';
import { assumptionsMade, consequencesFor, plainLanguageSummary, selfAssessmentSummary } from './summary.js';
import { buildThreatModel } from './threat-model.js';
import { triageRisk } from './triage.js';
import type { DeriveDesignDeps } from './types.js';
import { whatThisChanges } from './what-this-changes.js';

export function deriveDesign(profile: DesignProfile, deps: DeriveDesignDeps): DesignArtifacts {
  const now = deps.now ?? new Date();
  const f = profileFacts(profile);
  const hash = profileHash(profile);
  const previous = deps.previous;
  const sameProfile = previous?.profileHash === hash;

  const securityRequirements = deriveSecurityRequirements(profile, f);
  const architecture = deriveArchitecture(profile, f);
  const patterns = selectPatterns(profile, f, deps.knowledge.patterns);
  const checklist = fillChecklist(profile, f, deps.knowledge.sbdRules, deps.frameworks.sbd, deps.attestations ?? []);

  // A Claude-written threat model for the same profile is kept; otherwise the rule-based one is generated.
  const threatModel: ThreatModel =
    sameProfile && previous?.threatModel?.performedBy === 'claude' ? previous.threatModel : buildThreatModel(profile, f, architecture, now);

  const riskTriage = triageRisk(profile, f, checklist, threatModel, deps.escalationAcknowledgedAt);
  const adrs = deriveAdrs(profile, f, now, previous);
  const securityContract = securityContractFor(f);
  const buildSpec = buildSpecFor(profile);
  const applicability = computeApplicability(profile, buildSpec, deps.knowledge, deps.frameworks, {
    selfAssessment: deps.selfAssessment === true,
    ...(deps.uploaded ? { uploaded: deps.uploaded } : {}),
  });

  return {
    generatedAt: now.toISOString(),
    profileHash: hash,
    securityRequirements,
    architecture,
    patterns,
    checklist,
    ...(previous?.peerReview ? { peerReview: previous.peerReview } : {}),
    riskTriage,
    threatModel,
    adrs,
    securityContract,
    applicability,
    buildSpec,
    plainLanguageSummary: deps.selfAssessment ? selfAssessmentSummary(threatModel) : plainLanguageSummary(profile, f, riskTriage, threatModel),
    consequences: consequencesFor(profile, f),
    assumptionsMade: assumptionsMade(profile),
    whatThisChanges: whatThisChanges(profile, deps.knowledge.wizardCopy),
    ...(sameProfile && previous?.contractHash ? { contractHash: previous.contractHash } : {}),
  };
}

export { buildSpecFor, featuresFor, packageNameFor, renderBrief, sessionPolicyFor } from './build-spec.js';
export { whatThisChanges, WHAT_THIS_CHANGES_BUILTIN, type WhatThisChangesKey } from './what-this-changes.js';
export { renderDesignMarkdown, type RenderedDesign } from './render.js';
export { canonicalJson, profileHash, sha256Hex } from './hash.js';
export { profileFacts, effectiveRoles, listWords, audiencePhrase, deploymentPhrase, DATA_CATEGORY_LABELS, TLS_MODE_BY_DEPLOYMENT, type ProfileFacts } from './conditions.js';
export { deriveSecurityRequirements } from './requirements.js';
export { deriveArchitecture, COMPONENT_IDS, FLOW_IDS } from './architecture.js';
export { selectPatterns, fillTemplate } from './patterns.js';
export { fillChecklist, checklistTotals, raiseSeverity, SBD_SCORE } from './checklist.js';
export { triageRisk, escalationTriggers, SBD_THRESHOLD } from './triage.js';
export { buildThreatModel, riskLevel } from './threat-model.js';
export { deriveAdrs, ADR_FILES } from './adrs.js';
export { securityContractFor, SECURITY_CONTRACT_VERSION } from './contract.js';
export { plainLanguageSummary, consequencesFor, assumptionsMade } from './summary.js';
export type { DeriveDesignDeps, SbdChecklistView, SbdControlView, SbdSeverity, WizardCopyView } from './types.js';
