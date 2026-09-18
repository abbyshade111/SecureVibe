import { describe, expect, it } from 'vitest';
import { ADR_FILES, deriveDesign, renderDesignMarkdown } from '../../src/design/index.js';
import { frameworksForTests, makeKnowledge } from '../fixtures/design/knowledge.js';
import { clinicBookings, habitTracker } from '../fixtures/design/profiles.js';

const deps = { knowledge: makeKnowledge(), frameworks: frameworksForTests(), now: new Date('2026-09-16T10:00:00.000Z') };

describe('renderDesignMarkdown', () => {
  const design = deriveDesign(clinicBookings, deps);
  const files = renderDesignMarkdown(design, clinicBookings);

  it('returns the five design-freeze files', () => {
    expect(Object.keys(files).sort()).toEqual(['adrs', 'design.md', 'diagram.mmd', 'security-contract.md', 'threat-model.md']);
    expect(Object.keys(files.adrs)).toEqual(Object.values(ADR_FILES));
    expect(renderDesignMarkdown(design, clinicBookings)).toEqual(files);
  });

  it('design.md walks through every SbD step with tables', () => {
    const md = files['design.md'];
    expect(md).toMatch(/^# Clinic Bookings — design document/);
    for (const heading of [
      '## What we will build',
      '## Assumptions we made for you',
      '## 1. Security requirements (SbD step 1)',
      '## 2. Architecture (SbD step 2)',
      '## 3. Patterns applied (SbD step 3)',
      '## 4. SbD review checklist (SbD step 4)',
      '## 5. Second opinion (SbD step 5)',
      '## 6. Risk triage (SbD step 6)',
      '## 7. Threat model (SbD step 7)',
      '## 8. Decisions (ADRs)',
      '## 9. What will be verified after the build',
      '## 10. Build settings',
    ]) {
      expect(md, heading).toContain(heading);
    }
    expect(md).toContain('| SR-01 |');
    expect(md).toContain('| AS-01 |');
    expect(md).toContain('| DM-02 |');
    expect(md).toContain('```mermaid');
    expect(md).toContain(design.architecture.mermaid);
    expect(md).toContain('**Extra care.**');
    expect(md).toContain('Not performed yet');
    expect(md).toContain('Mitigation plans for critical controls answered "No"');
    expect(md).toContain('adr/ADR-001-authentication-model.md');
    expect(md).toContain('Package name: `clinic-bookings`');
    expect(md).not.toContain('undefined');
  });

  it('security-contract.md lists all rules with rationale and enforcement', () => {
    const md = files['security-contract.md'];
    expect(md).toContain('# Security contract (version 1.0)');
    for (const rule of design.securityContract.rules) {
      expect(md).toContain(`## ${rule.id}`);
      expect(md).toContain(rule.rule);
      expect(md).toContain(rule.rationale);
    }
    expect(md).toContain('_Enforced by:_ template, sast, dast, tests.');
    expect(md).toContain('AISVS C2.1.3');
  });

  it('threat-model.md has the register, details and action items', () => {
    const md = files['threat-model.md'];
    expect(md).toContain('# Threat model (STRIDE)');
    expect(md).toContain('## Risk register (highest risk first)');
    for (const t of design.threatModel!.threats) {
      expect(md).toContain(`| ${t.id} |`);
      expect(md).toContain(`### ${t.id} — `);
    }
    expect(md).toContain('## Action items');
    expect(md).toContain('HTTPS reverse proxy');
    expect(md).not.toContain('undefined');
  });

  it('diagram.mmd is the Mermaid source with a trailing newline', () => {
    expect(files['diagram.mmd']).toBe(`${design.architecture.mermaid}\n`);
    expect(files['diagram.mmd']).toMatch(/^flowchart LR/);
  });

  it('each ADR file has context, decision, alternatives and consequences', () => {
    for (const adr of design.adrs) {
      const md = files.adrs[ADR_FILES[adr.id]!]!;
      expect(md).toContain(`# ${adr.id}: ${adr.title}`);
      expect(md).toContain('## Context');
      expect(md).toContain('## Decision');
      expect(md).toContain('## Alternatives considered');
      expect(md).toContain('## Consequences');
      expect(md).toContain('Date: 2026-09-16');
    }
    expect(files.adrs['ADR-005-ai-boundary.md']).toContain('the assistant advises, application code decides');
  });

  it('renders a design without assumptions, peer review or open threats cleanly', () => {
    const simple = deriveDesign(habitTracker, deps);
    const out = renderDesignMarkdown(simple, habitTracker);
    expect(out['design.md']).not.toContain('## Assumptions we made for you');
    expect(out['design.md']).toContain('| N-A |');
    expect(out['threat-model.md']).toContain('## Action items');
    expect(out['design.md']).not.toContain('undefined');
    expect(out['threat-model.md']).not.toContain('undefined');
  });
});
