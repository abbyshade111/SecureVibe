/**
 * The questions an uploaded app needs, and only those.
 *
 * Somebody checking code they did not write cannot honestly answer half the wizard: which records it keeps, what
 * its features are, what it should be called. Guessing puts made-up facts into a report. What the answers decide
 * for an uploaded app is which rules apply (the applicability of ASVS and AISVS, the Secure by Design outcomes,
 * the target level), and that reads a small, fixed set of facts: who uses it and how they sign in, what kind of
 * information it holds, what it can do, where it runs and what an outage would cost. This list is those facts and
 * nothing else; server/src/design/conditions.ts and shared/profile.ts targetLevel are what read them.
 *
 * Everything else the full profile requires is filled in with a neutral default at design time
 * (withUploadedDefaults), named as such, so the check can run without anyone inventing an answer.
 */
import type { PartialDesignProfile } from './profile.js';

export const UPLOADED_QUESTION_IDS: readonly string[] = [
  'users.audience',
  'users.requiresSignIn',
  'users.registration',
  'users.centralSignIn',
  'data.categories',
  'data.aboutOtherPeople',
  'capabilities.fileUploads',
  'capabilities.aiAssistant.enabled',
  'capabilities.aiAssistant.canTakeActions',
  'capabilities.email',
  'capabilities.externalApis',
  'capabilities.scheduledJobs',
  'capabilities.publicApi',
  'capabilities.payments',
  'deployment.target',
  'deployment.businessImpact',
];

/** The wizard steps that hold at least one of those questions, in the wizard's order (the capability questions live in "features"). */
export const UPLOADED_STEP_IDS: readonly string[] = ['users', 'data', 'features', 'deployment'];

/** What an uploaded app's description says when nobody wrote one: a fact about the check, not a guess about the app. */
export const UPLOADED_DESCRIPTION = 'An app uploaded to SecureVibe to be checked as it is. SecureVibe did not build it and has no description of it beyond the answers given.';

/**
 * Fills the answers an uploaded app was never asked for with neutral defaults, so the full profile validates and
 * the design (which rules apply) can be derived. Nothing already answered is changed.
 */
export function withUploadedDefaults(profile: PartialDesignProfile, projectName: string): PartialDesignProfile {
  const next: PartialDesignProfile = structuredClone(profile);
  const app = (next.app ??= {});
  if (!app.name?.trim()) app.name = projectName.slice(0, 60) || 'Uploaded app';
  if (!app.description?.trim()) app.description = UPLOADED_DESCRIPTION;
  if (!app.category) app.category = 'other';
  const deployment = (next.deployment ??= {});
  const owner = (deployment.owner ??= {});
  if (!owner.name?.trim()) owner.name = 'The owner';
  // A placeholder that validates as an address and can reach nobody: the reports name the owner, not this.
  if (!owner.contactEmail?.trim()) owner.contactEmail = 'owner@example.com';
  next.meta ??= {};
  return next;
}
