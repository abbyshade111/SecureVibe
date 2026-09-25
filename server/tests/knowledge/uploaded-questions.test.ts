/** The short question set for uploaded apps: real question ids, only the facts applicability reads, and enough for a design. */
import { describe, expect, it } from 'vitest';
import { DesignProfileSchema } from '@shared/profile.js';
import { UPLOADED_QUESTION_IDS, UPLOADED_STEP_IDS, withUploadedDefaults } from '@shared/uploaded-questions.js';
import { loadKnowledge } from '../../src/frameworks/index.js';

describe('the questions an uploaded app is asked', () => {
  const copy = loadKnowledge({ warn: () => {} }).wizardCopy;

  it('are all real wizard questions, and only in the steps the short wizard shows', () => {
    const byId = new Map(copy.questions.map((q) => [q.id, q]));
    for (const id of UPLOADED_QUESTION_IDS) {
      const q = byId.get(id);
      expect(q, id).toBeDefined();
      expect(UPLOADED_STEP_IDS, `${id} is in step ${q!.step}`).toContain(q!.step);
    }
    // Nothing about what to build: records, features, looks, the description.
    for (const id of UPLOADED_QUESTION_IDS) expect(id.startsWith('app.'), id).toBe(false);
  });

  it('with the defaults, the short answers make a full profile a design can be derived from', () => {
    const short = {
      users: { audience: 'my-team', requiresSignIn: true, registration: 'admin-created', centralSignIn: 'no' },
      data: { categories: ['contact'], aboutOtherPeople: true },
      capabilities: { fileUploads: false, aiAssistant: { enabled: false, canTakeActions: false }, email: false, externalApis: [], scheduledJobs: false, publicApi: false, payments: false },
      deployment: { target: 'local-network', businessImpact: 'normal' },
    };
    const parsed = DesignProfileSchema.safeParse(withUploadedDefaults(short as never, 'Their app'));
    expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
    expect(parsed.data!.app.name).toBe('Their app');
    expect(parsed.data!.app.description).toMatch(/uploaded to SecureVibe/);
    // Nothing answered is touched.
    expect(parsed.data!.users.audience).toBe('my-team');
    expect(parsed.data!.data.categories).toEqual(['contact']);
    // Without the defaults the same answers are not a profile at all.
    expect(DesignProfileSchema.safeParse(short).success).toBe(false);
  });
});
