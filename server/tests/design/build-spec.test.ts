import { describe, expect, it } from 'vitest';
import { BuildSpecSchema } from '@shared/design.js';
import { buildSpecFor, packageNameFor, profileHash, sessionPolicyFor } from '../../src/design/index.js';
import { allProfiles, clinicBookings, habitTracker, marketplace, teamInventory } from '../fixtures/design/profiles.js';

describe('buildSpecFor', () => {
  it('validates and is deterministic for every fixture profile', () => {
    for (const { profile } of allProfiles) {
      const spec = buildSpecFor(profile);
      expect(() => BuildSpecSchema.parse(spec)).not.toThrow();
      expect(buildSpecFor(profile)).toEqual(spec);
      expect(spec.brief).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('derives sign-in from the audience and from features that need accounts', () => {
    expect(buildSpecFor(habitTracker).features.auth).toBe(false);
    const withUploads = { ...habitTracker, capabilities: { ...habitTracker.capabilities, fileUploads: true } };
    expect(buildSpecFor(withUploads).features.auth).toBe(true);
    expect(buildSpecFor(withUploads).features.uploads).toBe(true);
    const team = { ...habitTracker, users: { ...habitTracker.users, audience: 'my-team' as const } };
    expect(buildSpecFor(team).features.auth).toBe(true);
    expect(buildSpecFor(team).features.adminMfa).toBe(false);
  });

  it('forces admin MFA and field encryption for sensitive data or sensitive fields', () => {
    const sensitiveField = {
      ...teamInventory,
      users: { ...teamInventory.users, adminMfa: false },
      app: {
        ...teamInventory.app,
        entities: [{ ...teamInventory.app.entities[0]!, fields: [{ ...teamInventory.app.entities[0]!.fields[0]!, sensitive: true }] }],
      },
    };
    const spec = buildSpecFor(sensitiveField);
    expect(spec.features.fieldEncryption).toBe(true);
    expect(spec.features.adminMfa).toBe(true);
    expect(spec.brief).toContain('SENSITIVE: store with encryptField()');
  });

  it('maps deployment to TLS mode and LAN binding', () => {
    expect(buildSpecFor(habitTracker).features).toMatchObject({ tlsMode: 'off', lanBinding: false });
    expect(buildSpecFor(teamInventory).features).toMatchObject({ tlsMode: 'selfsigned', lanBinding: true });
    expect(buildSpecFor(clinicBookings).features).toMatchObject({ tlsMode: 'proxy', lanBinding: false });
  });

  it('turns on the scheduler for auto-deletion and email for invitations and open sign-up', () => {
    expect(buildSpecFor(clinicBookings).features).toMatchObject({ scheduler: true, retentionJobs: true, email: true });
    expect(buildSpecFor(teamInventory).features).toMatchObject({ scheduler: false, retentionJobs: false, email: true });
    const adminCreated = { ...teamInventory, users: { ...teamInventory.users, registration: 'admin-created' as const } };
    expect(buildSpecFor(adminCreated).features.email).toBe(false);
  });

  it('sets the session policy by target level', () => {
    expect(sessionPolicyFor(1)).toEqual({ idleMinutes: 30, absoluteHours: 12, maxConcurrent: 5 });
    expect(sessionPolicyFor(2)).toEqual({ idleMinutes: 15, absoluteHours: 8, maxConcurrent: 5 });
    expect(buildSpecFor(habitTracker).sessionPolicy.idleMinutes).toBe(30);
    expect(buildSpecFor(marketplace).sessionPolicy.idleMinutes).toBe(15);
  });

  it('derives a safe package name', () => {
    expect(packageNameFor('Clinic Bookings')).toBe('clinic-bookings');
    expect(packageNameFor('  Café & Bar!! ')).toBe('cafe-bar');
    expect(packageNameFor('---')).toBe('generated-app');
    expect(packageNameFor('x'.repeat(100))).toHaveLength(60);
    expect(buildSpecFor(marketplace).packageName).toBe('maker-market');
  });

  describe('the generation brief', () => {
    const brief = buildSpecFor(marketplace).brief;

    it('states purpose, audience, roles and registration', () => {
      expect(brief).toContain('# Generation brief: Maker Market');
      expect(brief).toContain(marketplace.app.description);
      expect(brief).toContain('Used by anyone on the internet');
      expect(brief).toContain('- admin (Administrator) — administrator');
      expect(brief).toContain('- maker (Maker)');
      expect(brief).toContain('Registration: open sign-up');
    });

    it('describes every entity with fields, types and access rules', () => {
      expect(brief).toContain('### listing — Listing (plural: Listings)');
      expect(brief).toContain('price (Price): money amount stored as an integer in minor units (cents); never a float; required');
      expect(brief).toContain('photo (Photo): an uploaded file: store the upload id from the uploads module, never a path; optional');
      expect(brief).toContain('Anyone may list and view these records (auth "public" on GET routes)');
      expect(brief).toContain('owner: { entity: "order", param: "id", ownerField: "owner_id" }');
      expect(brief).toContain('src/db/migrations/1NN_order.sql');
      expect(brief).toContain('tests/features/order.test.ts');
    });

    it('lists the features to build and what the template already provides', () => {
      expect(brief).toContain('- Search listings');
      expect(brief).toContain('AI assistant: purpose "answer buyer questions and draft listing descriptions"');
      expect(brief).toContain('It may take actions');
      expect(brief).toContain('Outside service "Shipping rates API"');
      expect(brief).toContain('It receives personal data');
      expect(brief).toContain('Public API: expose the records as JSON routes under /api/v1');
      expect(brief).toContain('never store, log or handle card numbers');
      expect(brief).toContain('## Already provided by the template');
      expect(brief).toContain('API keys feature');
      expect(brief).toContain('Field encryption helpers');
    });

    it('includes every security-contract rule and the definition of done', () => {
      for (let i = 1; i <= 25; i++) expect(brief).toContain(`- SC-${String(i).padStart(2, '0')}: `);
      expect(brief).toContain('## Definition of done');
      expect(brief).toContain('auth=true, adminMfa=true');
    });

    it('adapts to an app without accounts or entities', () => {
      const noEntities = { ...habitTracker, app: { ...habitTracker.app, entities: [] } };
      const b = buildSpecFor(noEntities).brief;
      expect(b).toContain('Sign-in: off');
      expect(b).toContain('(no accounts: this app has no sign-in)');
      expect(b).toContain('No records were specified');
      expect(b).not.toContain('Accounts: registration');
      expect(buildSpecFor(habitTracker).brief).toContain('This app has no sign-in: every route for this record uses auth "public"');
    });

    it('explains retention rules for personal data', () => {
      expect(buildSpecFor(clinicBookings).brief).toContain('deleted or pseudonymised after 24 months (RETENTION_MONTHS=24)');
      expect(buildSpecFor(teamInventory).brief).toContain('Retention: records are kept until deleted');
      expect(buildSpecFor(habitTracker).brief).not.toContain('Retention:');
    });
  });
});

// Why this is here: a rebuild carries an AI verdict forward when the cited file is byte-identical and the design
// profile hash is unchanged (pipeline/diff-aware.ts). Turning a feature off deletes that feature's files, which can
// leave a file that is byte-identical but no longer compiles, or means something different. Carrying a verdict
// across that would be dishonest, and the hash is the only thing standing between us and it. So the hash must move
// whenever the feature set moves. It does today because featuresFor reads only profile sections the hash covers,
// but nothing in the type system says so, and a future feature read from profile.meta would break it silently.
describe('a change of features is always a change of hash', () => {
  const caps = (overrides: Record<string, unknown>) => ({ ...marketplace, capabilities: { ...marketplace.capabilities, ...overrides } });

  // Deliberately stated as an implication rather than "each of these turns a feature off". Several of them do not:
  // a record with a file field needs uploads whatever the capability says, and an app with sign-in still sends
  // account email with email switched off. Those are the derivation working correctly, and writing the test the
  // other way round only pinned my guesses about it.
  const variants: { what: string; profile: typeof marketplace }[] = [
    { what: 'uploads off', profile: caps({ fileUploads: false, uploadKinds: [] }) },
    {
      what: 'uploads off and no file field on any record',
      profile: {
        ...caps({ fileUploads: false, uploadKinds: [] }),
        app: { ...marketplace.app, entities: marketplace.app.entities.map((e) => ({ ...e, fields: e.fields.filter((f) => f.type !== 'file') })) },
      },
    },
    { what: 'the AI assistant off', profile: caps({ aiAssistant: { ...marketplace.capabilities.aiAssistant, enabled: false } }) },
    { what: 'the assistant kept but not allowed to act', profile: caps({ aiAssistant: { ...marketplace.capabilities.aiAssistant, canTakeActions: false } }) },
    { what: 'email off', profile: caps({ email: false }) },
    { what: 'scheduled jobs off', profile: caps({ scheduledJobs: false }) },
    { what: 'the public API off', profile: caps({ publicApi: false }) },
    { what: 'payments off', profile: caps({ payments: false }) },
  ];

  it('never lets the feature set move while the hash stands still', () => {
    const before = buildSpecFor(marketplace).features;
    let moved = 0;
    for (const { what, profile } of variants) {
      const changedFeatures = JSON.stringify(buildSpecFor(profile).features) !== JSON.stringify(before);
      if (!changedFeatures) continue;
      moved += 1;
      expect(profileHash(profile), `${what} changes the feature set, so it must change the hash`).not.toBe(profileHash(marketplace));
    }
    // Without this the test would pass just as happily if nothing changed any features at all.
    expect(moved, 'the variants must actually move the feature set, or this proves nothing').toBeGreaterThan(3);
  });

  it('leaves both alone for bookkeeping that decides nothing', () => {
    const confirmed = { ...marketplace, meta: { ...marketplace.meta, confirmed: true } };
    expect(buildSpecFor(confirmed).features).toEqual(buildSpecFor(marketplace).features);
    expect(profileHash(confirmed)).toBe(profileHash(marketplace));
  });
});
