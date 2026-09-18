import { describe, expect, it } from 'vitest';
import { whatThisChanges } from '../../src/design/index.js';
import { clinicBookings, habitTracker } from '../fixtures/design/profiles.js';

describe('whatThisChanges', () => {
  it('returns empty lists for an empty profile and all five wizard keys', () => {
    expect(whatThisChanges({})).toEqual({ about: [], users: [], data: [], features: [], deployment: [] });
  });

  it('explains the baseline as soon as the app section exists', () => {
    const out = whatThisChanges({ app: { name: 'Habit Log' } });
    expect(out.about).toHaveLength(1);
    expect(out.about[0]).toMatch(/strict browser security headers/);
    expect(out.users).toEqual([]);
  });

  it('explains sign-in, roles, registration and MFA from the users section', () => {
    const out = whatThisChanges({
      app: { name: 'Shop Stock' },
      users: {
        audience: 'my-team',
        requiresSignIn: true,
        registration: 'invite-only',
        roles: [
          { name: 'manager', label: 'Manager', isAdmin: true },
          { name: 'staff', label: 'Shop staff', isAdmin: false },
        ],
        adminMfa: true,
      },
    });
    expect(out.users[0]).toBe('People must sign in with a password (12 characters or more) before using Shop Stock. Repeated wrong guesses lock the account for a while.');
    expect(out.users).toContainEqual(expect.stringContaining('Each role (Manager and Shop staff)'));
    expect(out.users).toContainEqual(expect.stringContaining('invitation link'));
    expect(out.users).toContainEqual(expect.stringContaining('Administrators need an authenticator app'));
    expect(out.users.join(' ')).not.toContain('authenticator app for their own account');
  });

  it('says there is no sign-in for a single person on this computer', () => {
    const out = whatThisChanges({ users: { audience: 'just-me', requiresSignIn: false } });
    expect(out.users).toEqual([expect.stringContaining('No sign-in')]);
  });

  it('explains sensitive and personal data, retention and region', () => {
    const out = whatThisChanges({
      app: { name: 'Clinic Bookings' },
      data: { categories: ['contact', 'health'], aboutOtherPeople: true, retention: 'auto-delete-after-period', retentionMonths: 24, region: 'eu-uk' },
    });
    expect(out.data[0]).toContain('Because Clinic Bookings handles health information, sensitive fields are encrypted');
    expect(out.data[1]).toContain('information about people (contact details and health information)');
    expect(out.data[2]).toBe('Records about people are deleted automatically after 24 months by a scheduled job.');
    expect(out.data[3]).toContain('GDPR');
  });

  it('says business-only when nothing about people is stored', () => {
    const out = whatThisChanges({ app: { name: 'Habit Log' }, data: { categories: ['business-confidential'] } });
    expect(out.data).toEqual(['Habit Log stores only business information, nothing about people, so no privacy notice or retention job is needed.']);
  });

  it('explains features and that they require accounts', () => {
    const out = whatThisChanges({
      app: { name: 'Maker Market' },
      users: { audience: 'just-me', requiresSignIn: false },
      capabilities: {
        fileUploads: true,
        aiAssistant: { enabled: true, purpose: '', dataItCanSee: 'users-own-records', canTakeActions: true, storesHistory: true, canSearchWeb: false, webSearchSites: [] },
        externalApis: [{ name: 'Shipping rates API', purpose: 'quotes', sendsPersonalData: true }],
        publicApi: true,
        payments: true,
        email: false,
        scheduledJobs: false,
        uploadKinds: [],
      },
    });
    expect(out.features[0]).toContain('people must sign in so records, quotas and budgets belong to someone');
    expect(out.features).toContainEqual(expect.stringContaining('Uploaded files are checked'));
    expect(out.features).toContainEqual("The assistant only sees the signed-in person's own records, always through the signed-in person's own permissions.");
    expect(out.features).toContainEqual(expect.stringContaining('nothing happens until the person confirms'));
    expect(out.features).toContainEqual(expect.stringContaining('Conversation history'));
    expect(out.features).toContainEqual(expect.stringContaining('Anthropic API key'));
    expect(out.features).toContainEqual(expect.stringContaining('Maker Market only talks to the outside services you named (Shipping rates API)'));
    expect(out.features).toContainEqual(expect.stringContaining('Personal data sent to Shipping rates API'));
    expect(out.features).toContainEqual(expect.stringContaining('API keys'));
    expect(out.features).toContainEqual(expect.stringContaining('never sees or stores card numbers'));
    expect(out.users).toContainEqual(expect.stringContaining('People must sign in'));
    expect(out.features.join(' ')).not.toContain('screened for harmful content');
  });

  it('adds moderation when customers or the public use the assistant', () => {
    const out = whatThisChanges({
      users: { audience: 'public', requiresSignIn: true },
      capabilities: { aiAssistant: { enabled: true, purpose: '', dataItCanSee: 'nothing', canTakeActions: false, storesHistory: false, canSearchWeb: false, webSearchSites: [] } },
    });
    expect(out.features).toContainEqual(expect.stringContaining('screened for harmful content'));
    expect(out.users).toContainEqual(expect.stringContaining('stricter rate limits'));
    expect(out.users).toContainEqual(expect.stringContaining('authenticator app for their own account'));
  });

  it('explains deployment, business impact and the owner', () => {
    const local = whatThisChanges({ app: { name: 'Habit Log' }, deployment: { target: 'local-only' } });
    expect(local.deployment).toEqual(['Habit Log listens on this computer only. Nothing else on the network can reach it, so no HTTPS certificate is needed.']);
    const lan = whatThisChanges({ deployment: { target: 'local-network', businessImpact: 'high', owner: { name: 'Priya Nair' } } });
    expect(lan.deployment[0]).toContain('local network over an encrypted (HTTPS) connection');
    expect(lan.deployment[1]).toContain('seriously hurt your business');
    expect(lan.deployment[2]).toBe('Priya Nair is named as the security contact in the incident plan and the reports.');
    expect(whatThisChanges({ deployment: { target: 'internet-later' } }).deployment[0]).toContain('HTTPS proxy');
  });

  it('prefers wizard-copy.json sentences when present, with placeholders filled', () => {
    const copy = { whatThisChanges: { auth: 'Custom: {appName} needs a password.', 'local-only': ['Line one.', 'Line two for {owner}.'] } };
    const out = whatThisChanges({ app: { name: 'Habit Log' }, users: { audience: 'my-team', requiresSignIn: true }, deployment: { target: 'local-only', owner: { name: 'Sam' } } }, copy);
    expect(out.users[0]).toBe('Custom: Habit Log needs a password.');
    expect(out.deployment.slice(0, 2)).toEqual(['Line one.', 'Line two for Sam.']);
  });

  it('works on full profiles too', () => {
    const full = whatThisChanges(clinicBookings);
    expect(full.users).toContainEqual(expect.stringContaining('Because Clinic Bookings handles sensitive information, administrators must use an authenticator app'));
    expect(full.features).toContainEqual(expect.stringContaining('Emails are cleaned'));
    expect(full.features).toContainEqual(expect.stringContaining('Scheduled jobs'));
    expect(whatThisChanges(habitTracker).features).toEqual([]);
  });
});
