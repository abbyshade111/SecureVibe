/**
 * Runs the engine against the real data/knowledge files when they exist. Other modules write those files; when
 * they are missing the test is skipped with a note rather than failing.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DesignArtifactsSchema } from '@shared/design.js';
import { deriveDesign, renderDesignMarkdown } from '../../src/design/index.js';
import { KNOWLEDGE_DIR, loadFrameworks, loadKnowledge } from '../../src/frameworks/index.js';
import { allProfiles } from '../fixtures/design/profiles.js';

const REQUIRED = ['sbd-rules.json', 'patterns.json', 'applicability.json'];
const present = REQUIRED.every((f) => existsSync(join(KNOWLEDGE_DIR, f)));

describe.skipIf(!present)('deriveDesign with the real data/knowledge files', () => {
  const knowledge = loadKnowledge({ warn: () => {} });
  const frameworks = loadFrameworks();

  for (const { name, profile } of allProfiles) {
    it(`${name}: validates, references known patterns and renders`, () => {
      const design = deriveDesign(profile, { knowledge, frameworks, now: new Date('2026-09-16T10:00:00.000Z') });
      expect(() => DesignArtifactsSchema.parse(design)).not.toThrow();
      expect(design.checklist).toHaveLength(36);
      // Every control got an outcome from the real rules (never the "no decision rule" fallback).
      expect(design.checklist.filter((e) => e.justification.startsWith('No decision rule'))).toEqual([]);
      expect(design.patterns.length).toBeGreaterThan(8);
      const catalogIds = new Set(knowledge.patterns.map((p) => p.id));
      for (const p of design.patterns) expect(catalogIds.has(p.id), p.id).toBe(true);
      for (const p of design.patterns) expect(p.why, p.id).toContain(profile.app.name);
      const files = renderDesignMarkdown(design, profile);
      expect(files['design.md'].length).toBeGreaterThan(5000);
      expect(files['design.md']).not.toContain('undefined');
    });
  }

  it('selects the CONTRACTS §5 always-on patterns for every profile and the conditional ones only when they apply', () => {
    const always = ['PAT-TRUST-ZONES', 'PAT-SECURE-DEFAULT-HEADERS', 'PAT-CONTRACT-FIRST-VALIDATION', 'PAT-FAIL-SECURE-ERRORS', 'PAT-OBSERVABILITY-EVENTS', 'PAT-AUDIT-CHAIN', 'PAT-IDEMPOTENT-MUTATIONS', 'PAT-TIMEOUTS-HEALTH', 'PAT-RATE-LIMITS', 'PAT-SECRETS-FROM-ENV', 'PAT-SBOM-PINNED-DEPS', 'PAT-IR-PLAN'];
    for (const { profile } of allProfiles) {
      const ids = deriveDesign(profile, { knowledge, frameworks }).patterns.map((p) => p.id);
      expect(ids).toEqual(expect.arrayContaining(always));
    }
    const local = deriveDesign(allProfiles[0]!.profile, { knowledge, frameworks }).patterns.map((p) => p.id);
    expect(local).not.toContain('PAT-ADMIN-MFA');
    expect(local).not.toContain('PAT-AI-GUARDRAILS');
    const market = deriveDesign(allProfiles[3]!.profile, { knowledge, frameworks }).patterns.map((p) => p.id);
    expect(market).toEqual(expect.arrayContaining(['PAT-ADMIN-MFA', 'PAT-AI-GUARDRAILS', 'PAT-AI-HUMAN-APPROVAL', 'PAT-API-KEYS', 'PAT-PROVIDER-HOSTED-PAYMENTS', 'PAT-TLS-PROXY', 'PAT-EGRESS-ALLOWLIST']));
  });
});

if (!present) {
  it('real knowledge files are absent (skipped)', () => {
    process.stdout.write(`[design] skipped real-knowledge test: ${REQUIRED.join(', ')} not all present in ${KNOWLEDGE_DIR}\n`);
    expect(present).toBe(false);
  });
}
