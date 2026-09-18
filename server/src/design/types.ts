/**
 * Inputs the design engine takes from other modules.
 *
 * `Knowledge` and `Frameworks` are the loader types from server/src/frameworks. The engine only reads
 * `knowledge.sbdRules`, `knowledge.patterns`, `knowledge.applicability`, `knowledge.wizardCopy` and
 * `frameworks.sbd.controls`, and hands both objects unchanged to `computeApplicability`.
 */
import type { DesignArtifacts } from '@shared/design.js';
import type { Attestation } from '@shared/project.js';
import type { Frameworks, Knowledge } from '../frameworks/index.js';

export type { Frameworks, Knowledge };

export type SbdSeverity = 'high' | 'medium' | 'low';

/** One checklist control as the frameworks loader exposes it (`frameworks.sbd.controls[n]`). */
export interface SbdControlView {
  id: string;
  domain: string; // "A".."E"
  statement: string;
  critical: boolean;
  severityIfNo: SbdSeverity;
}

/** The part of `frameworks.sbd` the checklist filler reads. */
export interface SbdChecklistView {
  controls: SbdControlView[];
}

/** data/knowledge/wizard-copy.json is free-form; the engine reads only `whatThisChanges` (keys = condition ids). */
export interface WizardCopyView {
  whatThisChanges?: Record<string, string | string[]>;
  [key: string]: unknown;
}

export interface DeriveDesignDeps {
  knowledge: Knowledge;
  frameworks: Frameworks;
  now?: Date;
  selfAssessment?: boolean;
  /** An app the owner uploaded to be checked (see computeApplicability). */
  uploaded?: { aiAssisted: boolean };
  attestations?: Attestation[];
  /**
   * Previous artifacts for the same project. The peer review is always carried over (it is a record of what
   * happened); a Claude-generated threat model is carried over only when the profile hash is unchanged.
   */
  previous?: DesignArtifacts;
  /** ISO timestamp of the owner's escalation acknowledgment, when recorded (project.escalationAcknowledgedAt). */
  escalationAcknowledgedAt?: string;
}
