import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ExampleProjectSchema } from '@shared/api.js';
import { DesignProfileSchema, targetLevel } from '@shared/profile.js';
import { readKnowledge } from './helpers.js';

const raw = readKnowledge<unknown>('examples.json');

describe('data/knowledge/examples.json', () => {
  const examples = z.array(ExampleProjectSchema).parse(raw);
  const byId = new Map(examples.map((e) => [e.id, e]));

  it('contains the four example projects with valid DesignProfiles', () => {
    expect([...byId.keys()].sort()).toEqual(['customer-portal', 'salon-booking', 'shop-inventory', 'team-tasks-ai']);
    for (const e of examples) {
      const parsed = DesignProfileSchema.safeParse(e.profile);
      expect(parsed.success, `${e.id}: ${parsed.success ? '' : z.prettifyError(parsed.error)}`).toBe(true);
      expect(e.profile.meta.startedFromExample).toBe(e.id);
      expect(e.profile.meta.confirmed).toBe(false);
    }
  });

  it('each example is realistic: several entities with fields, roles with one administrator, features listed', () => {
    for (const e of examples) {
      const p = e.profile;
      expect(p.app.entities.length, `${e.id} entities`).toBeGreaterThanOrEqual(3);
      for (const entity of p.app.entities) expect(entity.fields.length, `${e.id}/${entity.name} fields`).toBeGreaterThanOrEqual(2);
      expect(p.app.keyFeatures.length, `${e.id} features`).toBeGreaterThanOrEqual(4);
      expect(p.users.roles.filter((r) => r.isAdmin), `${e.id} exactly one admin role`).toHaveLength(1);
      expect(p.users.roles.length, `${e.id} roles`).toBeGreaterThanOrEqual(2);
      expect(p.data.categories, `${e.id} credentials category when sign-in is on`).toContain('credentials');
      expect(p.app.description.length, `${e.id} description`).toBeGreaterThan(200);
      if (p.data.retention === 'auto-delete-after-period') expect(p.data.retentionMonths, `${e.id} retentionMonths`).toBeDefined();
    }
  });

  it('salon booking: customers, open sign-up, email reminders, going online', () => {
    const p = byId.get('salon-booking')!.profile;
    expect(p.app.category).toBe('booking');
    expect(p.users.audience).toBe('customers');
    expect(p.capabilities.email).toBe(true);
    expect(p.deployment.target).toBe('internet-later');
    expect(p.app.entities.map((e) => e.name)).toContain('appointment');
    expect(p.app.entities.find((e) => e.name === 'appointment')!.access).toBe('owner-only');
  });

  it('shop inventory: team only on the shop network, business-confidential data, scheduled low-stock report', () => {
    const p = byId.get('shop-inventory')!.profile;
    expect(p.app.category).toBe('inventory');
    expect(p.users.audience).toBe('my-team');
    expect(p.data.categories).toContain('business-confidential');
    expect(p.capabilities.scheduledJobs).toBe(true);
    expect(p.deployment.target).toBe('local-network');
  });

  it('customer portal: documents via uploads, financial data, high impact, level 2', () => {
    const p = byId.get('customer-portal')!.profile;
    expect(p.capabilities.fileUploads).toBe(true);
    expect(p.capabilities.uploadKinds).toContain('documents');
    expect(p.data.categories).toEqual(expect.arrayContaining(['financial', 'files', 'contact']));
    expect(p.deployment.businessImpact).toBe('high');
    expect(p.app.entities.some((e) => e.fields.some((f) => f.type === 'file'))).toBe(true);
    expect(p.app.entities.some((e) => e.fields.some((f) => f.sensitive))).toBe(true);
    expect(targetLevel(p).level).toBe(2);
  });

  it('team task tracker: AI assistant enabled, read-only, with history', () => {
    const p = byId.get('team-tasks-ai')!.profile;
    expect(p.capabilities.aiAssistant.enabled).toBe(true);
    expect(p.capabilities.aiAssistant.purpose.length).toBeGreaterThan(20);
    expect(p.capabilities.aiAssistant.canTakeActions).toBe(false);
    expect(p.capabilities.aiAssistant.storesHistory).toBe(true);
    expect(p.capabilities.aiAssistant.dataItCanSee).toBe('all-records');
    expect(targetLevel(p).level).toBe(2);
  });

  it('example descriptions are written for a business owner, without technical jargon', () => {
    for (const e of examples) {
      expect(e.description).not.toMatch(/\b(?:SQL|API|JSON|HTTP|CSRF|JWT|OAuth)\b/);
      expect(e.title.length).toBeLessThan(60);
    }
  });
});
